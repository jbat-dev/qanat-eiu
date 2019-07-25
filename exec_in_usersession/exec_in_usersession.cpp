// exec_in_usersession.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <windows.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <atlbase.h>

#include "exec_in_usersession.h"
#include "testservice.h"


enum OPTION{
    EXEPATH     =0,
    EXEARG      =1,
    USERNAME    =2,
    LOGFILEPATH =3,
};
std::wstring g_optprefix(L"--xiu-");
std::map<int, std::wstring>g_optmap{
    {EXEPATH,       g_optprefix + L"exefullpath:"},
    {EXEARG,        g_optprefix + L"exearg:"},
    {USERNAME,      g_optprefix + L"un:"},
    {LOGFILEPATH,   g_optprefix + L"lf:"},
};

std::wofstream fout;

DWORD process::getProcessId(const std::wstring& name)
{
    fout << L"process::getProcessId (" << name << L")<<< " << std::endl;

    DWORD dwResult = 0;
    CHandle snapshot(CreateToolhelp32Snapshot(2, 0)); // 2=TH32CS_SNAPPROCESS
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    if (!Process32First(snapshot, &entry)) {
        return 0;
    }

    do {
        if (wcscmp(entry.szExeFile, name.c_str()) == 0) {
            dwResult = entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &entry));

    fout << L"  getProcessId() >>> " << dwResult << std::endl;
    return dwResult;
}

BOOL process::createProcessAsUser(const std::wstring& app, const std::wstring& param, HANDLE token, DWORD creationFlags, LPVOID env)
{
    fout << L"process::createProcessAsUser (app=" << app << L", param=" << param << L")<<< " << std::endl;

    wchar_t arg[MAX_PATH] = L"";
    DWORD dwError = 0;

    wcscpy_s(arg, (param.empty() ? app.c_str() : (app + L" " + param).c_str()));


    STARTUPINFO  si = { sizeof(STARTUPINFO), nullptr };
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    PROCESS_INFORMATION pi = {};
    const BOOL          retval = CreateProcessAsUser(token, nullptr, arg, nullptr, nullptr, FALSE, creationFlags, env, nullptr, &si, &pi);
    dwError = ::GetLastError();
    fout << L"  " << retval << L"= CreateProcessAsUser(" << arg << L")/dwError=" << dwError << std::endl;


    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return retval;
}


BOOL process::createProcess(const std::wstring& app, const std::wstring& param, HANDLE src_process)
{
    fout << L"process::createProcess (app=" << app << L", param=" << param << L")<<< " << std::endl;

    DWORD dwError = 0;

    if (src_process == nullptr) {
        fout << L"  src_process_handle is null." << std::endl;
        CHandle target(OpenProcess(MAXIMUM_ALLOWED, FALSE, getProcessId(L"explorer.exe")));
        dwError = ::GetLastError();
        if (!target) {
            fout << L"  OpenProcess(explorer.exe) failed. dwError=" << dwError << std::endl;
            return FALSE;
        }
        return createProcess(app, param, target);
    }

    // src process is specified. 
    CHandle processToken;
    if (!OpenProcessToken(src_process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
        fout << L"  OpenProcessToken() failed." << std::endl;
        return FALSE;
    }

    CHandle userToken;
    if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
        fout << L"  DuplicateTokenEx() failed." << std::endl;
        return FALSE;
    }

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetProcessId(src_process), &sessionId);

    DWORD  creationFlags = CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS;
    LPVOID env = nullptr;
    SetTokenInformation(userToken, TokenSessionId, &sessionId, sizeof(DWORD));

    if (CreateEnvironmentBlock(&env, userToken, TRUE)) {
        creationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }
    else {
        fout << L"  CreateEnvironmentBlock() failed." << std::endl;
        env = nullptr;
    }

    if (!createProcessAsUser(app, param, userToken, creationFlags, env)) {
        fout << L"  createProcessAsUser() failed." << std::endl;
        return FALSE;
    }

    if (env != nullptr) {
        DestroyEnvironmentBlock(env);
    }

    return TRUE;
}



// プロセス名とユーザー名から、プロセストークン（オリジナル）の取得
HANDLE process::getProcessHandleWithUserName(const std::wstring& pname, std::wstring* puname) {

    fout << L"process::getProcessHandleWithUserName (" << pname + L", " + ((puname == nullptr) ? L"nullptr" : *puname) << L")<<< " << std::endl;

    HANDLE hResult = 0;
    DWORD dwError = 0;
    CHandle snapshot(CreateToolhelp32Snapshot(2, 0)); // 2=TH32CS_SNAPPROCESS
    if (snapshot == INVALID_HANDLE_VALUE) {
        fout << L"  process::getProcessHandleWithUserName : failed at CreateToolhelp32Snapshot." << std::endl;
        return nullptr;
    }

    // プロセスサーチ
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    if (!Process32First(snapshot, &entry)) {
        return nullptr;
    }

    // name check 
    do {
        HANDLE hProcessCheck = nullptr;
        // check name
        if (_wcsicmp(entry.szExeFile, pname.c_str()) != 0) {
            continue;
        }

        // yes. 
        // get process handle.
        hProcessCheck = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
        dwError = ::GetLastError();
        if (hProcessCheck == nullptr) {
            continue;
        }

        // get process token & DUPLICATE (important!).
        CHandle processToken;
        if (!OpenProcessToken(hProcessCheck, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
            dwError = ::GetLastError();
            ::CloseHandle(hProcessCheck);
            continue;
        }
        CHandle userToken;
        if (!DuplicateTokenEx(processToken.m_h, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
            ::CloseHandle(hProcessCheck);
            continue;
        }

        // if user not specified, use the first one.
        if (puname == nullptr || puname->length() == 0) {
            hResult = hProcessCheck;
            break;
        }
        std::wstring uname(*puname);

        // control user token information
        // get username
        wchar_t wchaUserName[260] = { 0 };
        DWORD dwSizeUserName = sizeof(wchaUserName) / sizeof(wchar_t);
        {
            wchar_t wchaDomainName[260] = { 0 };
            DWORD   dwSizeDomain = sizeof(wchaDomainName) / sizeof(wchar_t);
            SID_NAME_USE sidName;
            DWORD dwNeeded = 0, dwSize = 0;

            GetTokenInformation(userToken.m_h, TokenUser, NULL, 0, &dwSize);
            PTOKEN_USER pbyBuf = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
            if (pbyBuf == nullptr) {
                ::CloseHandle(hProcessCheck);
                continue;
            }
            if (!GetTokenInformation(userToken.m_h, TokenUser, (void*)pbyBuf, dwSize, &dwNeeded)) {
                ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
                ::CloseHandle(hProcessCheck);
                continue;
            }
            if (!LookupAccountSid(NULL, pbyBuf->User.Sid, wchaUserName, &dwSizeUserName, wchaDomainName, &dwSizeDomain, &sidName)) {
                ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
                ::CloseHandle(hProcessCheck);
                continue;
            }
            ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
        }

        // check
        if (_wcsicmp(uname.c_str(), (const wchar_t*)wchaUserName) != 0) {
            fout << L"  process::getProcessHandleWithUserName : not mached. found=" << wchaUserName << std::endl;
            ::CloseHandle(hProcessCheck);
            continue;
        }

        // yes 
        fout << L"  process::getProcessHandleWithUserName : We got a expected user's process handle." << std::endl;
        hResult = hProcessCheck;
        break;
    } while (Process32Next(snapshot, &entry));
    ::CloseHandle(snapshot);

    return hResult;
}



// function to check test framwork
int process::test(int x) 
{
    return x;
}


// parseOption
int parseOption(wchar_t** argv, int argc, std::map<std::wstring, std::wstring>& option) {
    if (argc < 2) {
        return 0;
    }
    std::wstring wstrExeName(argv[1]);
    option.insert(std::make_pair(g_optmap.at(EXEPATH), wstrExeName));

    int i = 2;
    std::wstring wstrExeArg(L"");
    if (argc >= 3 && std::wstring(argv[2]).find(g_optprefix) != 0) {
        wstrExeArg = argv[2];
        i++;
    }
    option.insert(std::make_pair(g_optmap.at(EXEARG), wstrExeArg));
    
    for (; i < argc; i++) {

        std::wstring wstr(argv[i]);

        fout << wstr << std::endl;
        if (wstr.find(g_optprefix) != 0) {
            fout << L"unkown option," + wstr << std::endl;
            continue;
        }
        // option key
        std::wstring wstrKey;
        std::wstring wstrValue;

        std::wstring::size_type pos;

        pos = wstr.find(L":");
        if (pos == std::wstring::npos) {
            fout << L"unkown option," + wstr << std::endl;
            continue;
        }

        wstrKey = wstr.substr(0, pos + 1);
        wstrValue = wstr.substr(pos + 1);
        fout << L"key=" + wstrKey + L", value=" + wstrValue << std::endl;

        option.insert(std::make_pair(wstrKey, wstrValue));
    }
    return 1;
}


// logfile 
int processOption_logfilefullpath(std::map<std::wstring, std::wstring>& option) {
    std::wstring wstrFileFullPath;
    std::ios_base::openmode fmode = 0;

    if (option.find(g_optmap.at(LOGFILEPATH)) != option.end()) {
        wstrFileFullPath = option.at(g_optmap.at(LOGFILEPATH));
    }    
    fout.open(wstrFileFullPath.c_str(), std::ios::in | std::ios::out | std::ios::trunc);
    fout << wstrFileFullPath << std::endl;
    return 1;
}


// main_exit
int main_exit(int ret_code) {
    fout.close();
    return ret_code;
}


// main
int wmain(int argc, wchar_t** argv)
{
    int iRet = 0;
    _wsetlocale(LC_ALL, _T(""));

    // check service mode
    if (_wcsicmp(argv[1], L"--register") == 0) { 
        service::registerService();
        return main_exit(0);
    }
    if (_wcsicmp(argv[1], L"--unregister") == 0) { 
        service::unregisterService();
        return main_exit(0);
    }
    if (_wcsicmp(argv[1], L"--start") == 0) { 
        SERVICE_TABLE_ENTRY services[] = {
            { service::SERVICE_NAME, &service::serviceMain }, { nullptr, nullptr }
        };
        StartServiceCtrlDispatcher(services);
        return main_exit(0);
    }
  

    // this is main stream.
    if (argc <= 1) {
        fout << L"One argument required at least." << std::endl;
        return main_exit(0);
    }

    std::map<std::wstring, std::wstring> option;
    parseOption(argv, argc, option);
    {
        processOption_logfilefullpath(option);
    }

    std::wstring wstrExeName(option.at(g_optmap.at(EXEPATH)));
    std::wstring wstrExeArg(option.at(g_optmap.at(EXEARG)));
    std::wstring wstrUserName(L"");
    if (option.find(g_optmap.at(USERNAME)) != option.end()) {
        wstrUserName = option.at(g_optmap.at(USERNAME));
    }
    
    CHandle h(process::getProcessHandleWithUserName(L"explorer.exe", &wstrUserName));
    iRet = process::createProcess(wstrExeName, wstrExeArg, h.m_h);
    return main_exit(iRet);
}

