// exec_in_usersession.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <atlbase.h>

#include "exec_in_usersession.h"

DWORD process::getProcessId(const std::wstring& name)
{
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

    return dwResult;
}

BOOL process::createProcessAsUser(const std::wstring& app, const std::wstring& param, HANDLE token, DWORD creationFlags, LPVOID env)
{
    wchar_t arg[MAX_PATH] = L"";

    wcscpy_s(arg, (param.empty() ? app.c_str() : (app + L" " + param).c_str()));

    STARTUPINFO  si = { sizeof(STARTUPINFO), nullptr };
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    PROCESS_INFORMATION pi = {};
    const BOOL          retval = CreateProcessAsUser(token, nullptr, arg, nullptr, nullptr, FALSE, creationFlags, env, nullptr, &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return retval;
}


BOOL process::createProcess(const std::wstring& app, const std::wstring& param, HANDLE src_process)
{
    if (src_process == nullptr) {
        CHandle target(OpenProcess(MAXIMUM_ALLOWED, FALSE, getProcessId(L"explorer.exe")));
        if (!target) {
            return FALSE;
        }
        return createProcess(app, param, target);
    }

    // src process is specified. 
    CHandle processToken;
    if (!OpenProcessToken(src_process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
        return FALSE;
    }

    CHandle userToken;
    if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
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
        env = nullptr;
    }

    createProcessAsUser(app, param, userToken, creationFlags, env);

    if (env != nullptr) {
        DestroyEnvironmentBlock(env);
    }

    return FALSE;
}



// プロセス名とユーザー名から、プロセストークン（オリジナル）の取得
HANDLE process::getProcessTokenHandleWithUserName(const std::wstring& pname, std::wstring* puname) {
    HANDLE hResult = 0;
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

        // get process token & DUPLICATE (important!).
        CHandle processToken;
        if (!OpenProcessToken(hProcessCheck, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
            continue;
        }
        CHandle userToken;
        if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
            continue;
        }

        // if user not specified, use the first one.
        if (puname == nullptr || puname->length() == 0) {
            hResult = processToken.m_h;
            break;
        }
        std::wstring uname(*puname);

        // get username
        wchar_t wchaUserName[260] = { 0 };
        DWORD dwSizeUserName = sizeof(wchaUserName) / sizeof(wchar_t);
        {
            wchar_t wchaDomainName[260] = { 0 };
            DWORD   dwSizeDomain = sizeof(wchaDomainName) / sizeof(wchar_t);
            SID_NAME_USE sidName;
            DWORD dwNeeded = 0, dwSize = 0;

            GetTokenInformation(processToken, TokenUser, NULL, 0, &dwSize);
            PTOKEN_USER pbyBuf = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
            if (pbyBuf == nullptr) {
                continue;
            }
            if (!GetTokenInformation(processToken, TokenUser, (void*)pbyBuf, dwSize, &dwNeeded) ||
                !LookupAccountSid(NULL, pbyBuf->User.Sid, wchaUserName, &dwSizeUserName, wchaDomainName, &dwSizeDomain, &sidName)) {
                ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
                continue;
            }
            ::HeapFree(GetProcessHeap(), 0, (void*)pbyBuf);
        }

        // check
        if (_wcsicmp(uname.c_str(), (const wchar_t*)wchaUserName) != 0) {
            continue;
        }

        // yes 
        hResult = processToken.m_h;
        break;
    } while (Process32Next(snapshot, &entry));

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

    CHandle h(process::getProcessTokenHandleWithUserName(L"explorer.exe", &wstrUserName));
    return process::createProcess(wstrExeName, wstrExeArg, h);
}

