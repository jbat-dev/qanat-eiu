#ifndef PROCESS_HPP_20100714_
#define PROCESS_HPP_20100714_


#if defined(_MSC_VER) && (_MSC_VER >= 1020)
# pragma once
#endif

namespace process {
    DWORD   getProcessId(const std::wstring& name);
    BOOL    createProcessAsUser(const std::wstring& app, const std::wstring& param, HANDLE token, DWORD creationFlags, LPVOID env);
    BOOL    createProcess(const std::wstring& app, const std::wstring& param, HANDLE process = nullptr);
    HANDLE  getProcessHandleWithUserName(const std::wstring& pname, std::wstring* puname = nullptr);
    int  test(int);
}

#endif

#pragma comment(lib, "userenv.lib")

extern std::wofstream fout;
