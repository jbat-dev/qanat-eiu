// exec_in_usersession.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <atlbase.h>

#include "exec_in_usersession.h"
#include "testservice.h"


std::wofstream fout;


DWORD process::getProcessId(const std::wstring& name)
{
    std::wcout << L"process::getProcessId (" << name << L")<<< " << std::endl;

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

    std::wcout << L"  getProcessId() >>> " << dwResult << std::endl;
    return dwResult;
}

BOOL process::createProcessAsUser(const std::wstring& app, const std::wstring& param, HANDLE token, DWORD creationFlags, LPVOID env)
{
    std::wcout << L"process::createProcessAsUser (app=" << app << L", param=" << param << L")<<< " << std::endl;
    fout << L"process::createProcessAsUser (app=" << app << L", param=" << param << L")<<< " << std::endl;

    wchar_t arg[MAX_PATH] = L"";
    DWORD dwError = 0;

    wcscpy_s(arg, (param.empty() ? app.c_str() : (app + L" " + param).c_str()));

    STARTUPINFO  si = { sizeof(STARTUPINFO), nullptr };
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    PROCESS_INFORMATION pi = {};
    const BOOL          retval = CreateProcessAsUser(token, nullptr, arg, nullptr, nullptr, FALSE, creationFlags, env, nullptr, &si, &pi);
    dwError = ::GetLastError();
    std::wcout << L"  " << retval << L"= CreateProcessAsUser()/dwError=" << dwError << std::endl;
    fout << L"  " << retval << L"= CreateProcessAsUser(" << arg << L")/dwError=" << dwError << std::endl;


    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return retval;
}


BOOL process::createProcess(const std::wstring& app, const std::wstring& param, HANDLE src_process)
{
    std::wcout << L"process::createProcess (app=" << app << L", param=" << param << L")<<< " << std::endl;
    fout << L"process::createProcess (app=" << app << L", param=" << param << L")<<< " << std::endl;

    DWORD dwError = 0;

    if (src_process == nullptr) {
        std::wcout << L"  src_process_handle is null." << std::endl;
        CHandle target(OpenProcess(MAXIMUM_ALLOWED, FALSE, getProcessId(L"explorer.exe")));
        dwError = ::GetLastError();
        if (!target) {
            std::wcout << L"  OpenProcess(explorer.exe) failed. dwError=" << dwError << std::endl;
            fout << L"  OpenProcess(explorer.exe) failed. dwError=" << dwError << std::endl;
            return FALSE;
        }
        return createProcess(app, param, target);
    }

    // src process is specified. 
    CHandle processToken;
    if (!OpenProcessToken(src_process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
        std::wcout << L"  OpenProcessToken() failed." << std::endl;
        return FALSE;
    }

    CHandle userToken;
    if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
        std::wcout << L"  DuplicateTokenEx() failed." << std::endl;
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
        std::wcout << L"  CreateEnvironmentBlock() failed." << std::endl;
        env = nullptr;
    }

    if (!createProcessAsUser(app, param, userToken, creationFlags, env)) {
        std::wcout << L"  createProcessAsUser() failed." << std::endl;
        return FALSE;
    }

    if (env != nullptr) {
        DestroyEnvironmentBlock(env);
    }

    return TRUE;
}



// プロセス名とユーザー名から、プロセストークン（オリジナル）の取得
HANDLE process::getProcessHandleWithUserName(const std::wstring& pname, std::wstring* puname) {

    std::wcout << L"process::getProcessHandleWithUserName (" << pname + L", " + ((puname == nullptr) ? L"nullptr" : *puname) << L")<<< " << std::endl;

    HANDLE hResult = 0;
    DWORD dwError = 0;
    CHandle snapshot(CreateToolhelp32Snapshot(2, 0)); // 2=TH32CS_SNAPPROCESS
    if (snapshot == INVALID_HANDLE_VALUE) {
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
            ::CloseHandle(hProcessCheck);
            continue;
        }

        // yes 
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

// main
int wmain(int argc, wchar_t** argv)
{
    _wsetlocale(LC_ALL, _T(""));


    if (argc <= 1) {
        std::wcout << L"One argument required at least." << std::endl;
        return 0;
    }

    // check service mode
    if (_wcsicmp(argv[1], L"--register") == 0) { 
        service::registerService();
        return 0;
    }
    
    if (_wcsicmp(argv[1], L"--unregister") == 0) { 
        service::unregisterService();
        return 0;
    }
    if (_wcsicmp(argv[1], L"--start") == 0) { 

//        std::wstring strLogFileName = L"c:\\temp\\log.txt";
//        fout.open(L"c:\\temp\\log2.txt", std::ios::app);

//        fout << L"starting testservice ..." << std::endl;

        SERVICE_TABLE_ENTRY services[] = {
            { service::SERVICE_NAME, &service::serviceMain }, { nullptr, nullptr }
        };
        StartServiceCtrlDispatcher(services);

//        fout << L"ending testservice ..." << std::endl;
//        fout << std::endl;
//        fout << std::endl;
//        fout.close();

        return 0;
    }

  

    // this is main stream.
    fout.open(L"c:\\temp\\log2.txt", std::ios::app);

    std::wstring wstrExeName(L"");
    if (argc >=2){
        wstrExeName = argv[1];
    }

    std::wstring wstrExeArg(L"");
    if (argc >= 3) {
        wstrExeArg = argv[2];
    }

    std::wstring wstrUserName(L"");
    if (argc >= 4) {
        wstrUserName = argv[3];
    }

    std::wcout << L"app=" + wstrExeName << std::endl;
    std::wcout << L"arg=" + wstrExeArg << std::endl;
    std::wcout << L"unm=" + wstrUserName << std::endl;

    CHandle h(process::getProcessHandleWithUserName(L"explorer.exe", &wstrUserName));
    return process::createProcess(wstrExeName, wstrExeArg, h.m_h);
}

