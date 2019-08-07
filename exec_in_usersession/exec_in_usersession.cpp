// exec_in_usersession.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <ctime>
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

#pragma warning(push)
#pragma warning(disable:4996)
#define LOG(x) {std::time_t t= std::time(nullptr); std::wstring MSG; fout << std::asctime(std::localtime(&t)) << L"\t" << MSG << L"[" << FUNCNAME << L"]" << L":" << x  << std::endl;}
#define RETURN(x) {std::wstring MSG; fout << MSG << L"[" << FUNCNAME << L"]" << L":>>> " << x << std::endl; return x;}

std::wofstream fout;

DWORD process::getProcessId(const std::wstring& name)
{
    static const wchar_t FUNCNAME[] = L"process::getProcessId";
    LOG(L"<<<");
    LOG(L"  name:" << name );

    DWORD dwResult = 0;
    CHandle snapshot(CreateToolhelp32Snapshot(2, 0)); // 2=TH32CS_SNAPPROCESS
    if (snapshot == INVALID_HANDLE_VALUE) {
        RETURN(0);
    }

    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    if (!Process32First(snapshot, &entry)) {
        RETURN(0);
    }

    do {
        if (wcscmp(entry.szExeFile, name.c_str()) == 0) {
            dwResult = entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &entry));

    fout << L"  getProcessId() >>> " << dwResult << std::endl;
    RETURN(dwResult);
}

///////////////////////////////////////////////////////////////////////////////////
BOOL process::createProcessAsUser(const std::wstring& app, const std::wstring& param, HANDLE token, DWORD creationFlags, LPVOID env)
{
    static const wchar_t FUNCNAME[] = L"process::createProcessAsUser";
    LOG(L"  <<<");

    LOG(L"  app=" << app << L"param=" << param);

    wchar_t arg[MAX_PATH] = L"";
    DWORD dwError = 0;

    wcscpy_s(arg, (param.empty() ? app.c_str() : (app + L" " + param).c_str()));


    STARTUPINFO  si = { sizeof(STARTUPINFO), nullptr };
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    PROCESS_INFORMATION pi = {};
    const BOOL          retval = CreateProcessAsUser(token, nullptr, arg, nullptr, nullptr, FALSE, creationFlags, env, nullptr, &si, &pi);
    dwError = ::GetLastError();
    LOG(L"  " << retval << L"= CreateProcessAsUser()/dwError=" << dwError);


    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    RETURN(retval);
}


///////////////////////////////////////////////////////////////////////////////////
BOOL process::createProcess(const std::wstring& app, const std::wstring& param, HANDLE src_process)
{
    static const wchar_t FUNCNAME[] = L"process::createProcess";
    LOG(L"<<<");

    LOG(L"  app=" << app << L", param=" << param << L"src_process=" << src_process);

    DWORD dwError = 0;

    if (src_process == nullptr) {
        LOG(L"  src_process_handle is null.");
        CHandle target(OpenProcess(MAXIMUM_ALLOWED, FALSE, getProcessId(L"explorer.exe")));
        dwError = ::GetLastError();
        if (!target) {
            LOG(L"  OpenProcess(explorer.exe) failed. dwError=" << dwError);
            RETURN(FALSE);
        }
        RETURN(createProcess(app, param, target));
    }

    // src process is specified. 
    CHandle processToken;
    if (!OpenProcessToken(src_process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
        dwError = ::GetLastError();
        LOG(L"  OpenProcessToken() failed./dwError=" << dwError);
        RETURN(FALSE);
    }

    CHandle userToken;
    if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
        dwError = ::GetLastError();
        LOG(L"  DuplicateTokenEx() failed./dwError=" << dwError);
        RETURN(FALSE);
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
        dwError = ::GetLastError();
        LOG(L"  CreateEnvironmentBlock() failed./dwError=" << dwError);
        env = nullptr;
    }

    if (!createProcessAsUser(app, param, userToken, creationFlags, env)) {
        dwError = ::GetLastError();
        LOG(L"  createProcessAsUser() failed./dwError=" << dwError);
        RETURN(FALSE);
    }

    if (env != nullptr) {
        DestroyEnvironmentBlock(env);
    }

    RETURN(TRUE);
}


///////////////////////////////////////////////////////////////////////////////////
// プロセス名とユーザー名から、プロセストークン（オリジナル）の取得
HANDLE process::getProcessHandleWithUserName(const std::wstring& pname, std::wstring* puname) {
    static const wchar_t FUNCNAME[] = L"process::getProcessHandleWithUserName";
    LOG(L"<<<");
    LOG(L"  pname=" << pname << L",puname=" << ((puname == NULL) ? L"nullptr" : *puname));

    HANDLE hResult = 0;
    DWORD dwError = 0;
    CHandle snapshot(CreateToolhelp32Snapshot(2, 0)); // 2=TH32CS_SNAPPROCESS
    if (snapshot == INVALID_HANDLE_VALUE) {
        LOG(L"  failed at CreateToolhelp32Snapshot.dwError=" << dwError );
        RETURN(NULL);
    }

    // プロセスサーチ
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    dwError = ::GetLastError();
    if (!Process32First(snapshot, &entry)) {
        LOG(L"  failed at Process32First./dwError=" << dwError );
        RETURN(NULL);
    }

    // name check 
    do {
        HANDLE hProcessCheck = nullptr;
        // check name
        if (_wcsicmp(entry.szExeFile, pname.c_str()) != 0) {
            LOG(L"  info:process name not matched./" << entry.szExeFile);
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
            LOG(L"  failed at OpenProcessToken()/dwError=" << dwError);
            continue;
        }
        CHandle userToken;
        if (!DuplicateTokenEx(processToken.m_h, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
            dwError = ::GetLastError();
            ::CloseHandle(hProcessCheck);
            LOG(L"  failed at DuplicateTokenEx()/dwError=" << dwError);
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
            dwError = ::GetLastError();
            if (pbyBuf == nullptr) {
                LOG(L"  failed at HeapAlloc()/dwError=" << dwError);
                ::CloseHandle(hProcessCheck);
                continue;
            }
            if (!GetTokenInformation(userToken.m_h, TokenUser, (void*)pbyBuf, dwSize, &dwNeeded)) {
                dwError = ::GetLastError();
                LOG(L"  failed at GetTokenInformation()/dwError=" << dwError);
                ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
                ::CloseHandle(hProcessCheck);
                continue;
            }
            if (!LookupAccountSid(NULL, pbyBuf->User.Sid, wchaUserName, &dwSizeUserName, wchaDomainName, &dwSizeDomain, &sidName)) {
                dwError = ::GetLastError();
                LOG(L"  failed at LookupAccountSid()/dwError=" << dwError);
                ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
                ::CloseHandle(hProcessCheck);
                continue;
            }
            ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
        }

        // check
        if (_wcsicmp(uname.c_str(), (const wchar_t*)wchaUserName) != 0) {
            LOG(L"  not mached. found=" << wchaUserName);
            ::CloseHandle(hProcessCheck);
            continue;
        }

        // yes 
        LOG(L"  We got a expected user's process handle.");
        hResult = hProcessCheck;
        break;
    } while (Process32Next(snapshot, &entry));
    ::CloseHandle(snapshot);
    RETURN(hResult);
}


///////////////////////////////////////////////////////////////////////////////////
// function to check test framwork
int process::test(int x) 
{
    return x;
}

///////////////////////////////////////////////////////////////////////////////////
// parseOption
int parseOption(wchar_t** argv, int argc, std::map<std::wstring, std::wstring>& option) {
    static const wchar_t FUNCNAME[] = L"parseOption";

    if (argc < 2) {
        RETURN(0);
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
            LOG(L"  unkown option," + wstr);
            continue;
        }
        // option key
        std::wstring wstrKey;
        std::wstring wstrValue;

        std::wstring::size_type pos;

        pos = wstr.find(L":");
        if (pos == std::wstring::npos) {
            LOG(L"  unkown option,:" + wstr);
            continue;
        }

        wstrKey = wstr.substr(0, pos + 1);
        wstrValue = wstr.substr(pos + 1);
        LOG(L"  key=" + wstrKey + L", value=" + wstrValue);

        option.insert(std::make_pair(wstrKey, wstrValue));
    }
    RETURN(1);
}

///////////////////////////////////////////////////////////////////////////////////
// logfile 
int processOption_logfilefullpath(std::map<std::wstring, std::wstring>& option) {
    static const wchar_t FUNCNAME[] = L"processOption_logfilefullpath";
    std::wstring wstrFileFullPath;
    std::ios_base::openmode fmode = 0;

    if (option.find(g_optmap.at(LOGFILEPATH)) != option.end()) {
        wstrFileFullPath = option.at(g_optmap.at(LOGFILEPATH));
    }    
    fout.open(wstrFileFullPath.c_str(), std::ios::in | std::ios::out | std::ios::trunc);
    fout << wstrFileFullPath << std::endl;
    RETURN(1);
}

///////////////////////////////////////////////////////////////////////////////////
// main_exit
int main_exit(int ret_code) {
    static const wchar_t FUNCNAME[] = L"main_exit";
    fout.close();
    return ret_code;
}


///////////////////////////////////////////////////////////////////////////////////
// main 
int wmain(int argc, wchar_t** argv)
{
    static const wchar_t FUNCNAME[] = L"wmain";
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
    LOG(L"  >>>");
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


#pragma warning(pop)
