#ifndef PROCESS_HPP_20100714_
#define PROCESS_HPP_20100714_


#if defined(_MSC_VER) && (_MSC_VER >= 1020)
# pragma once
#endif

namespace process {
    BOOL createProcess(const std::wstring& app, const std::wstring& param, HANDLE process = nullptr);
    int  test(int);
}

#endif

#pragma comment(lib, "userenv.lib")
