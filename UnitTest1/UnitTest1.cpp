#include "pch.h"
#include "CppUnitTest.h"

#include <iostream>
#include <string>
#include <windows.h>

#include "..\exec_in_usersession\exec_in_usersession.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest1_functionlevel
{
    TEST_CLASS(_dummyTest)
    {
    public:
        
        TEST_METHOD(dummyTest)
        {
            Assert::AreEqual(99, process::test(99));
        }
    };
    TEST_CLASS(_getProcessId)
    {
    public:

        TEST_METHOD(getProcessId)
        {
            Assert::AreNotEqual((DWORD)0, process::getProcessId(L"explorer.exe"));
            Assert::AreEqual((DWORD)0, process::getProcessId(L"nothing"));
        }
    };
    TEST_CLASS(_getProcessTokenWithUserName)
    {
    public:
        TEST_METHOD(getProcessTokenHandleWithUserName__pname)
        {
            // existing process
            HANDLE h = process::getProcessTokenHandleWithUserName(L"explorer.exe");
            Assert::AreNotEqual((void*)0, (void*)h);
            ::CloseHandle(h);
        }

        TEST_METHOD(getProcessTokenHandleWithUserName__invalidpname)
        {
            // non-existing process
            HANDLE h = process::getProcessTokenHandleWithUserName(L"explorer.exe.none");
            Assert::AreEqual((void*)0, (void*)h);
            ::CloseHandle(h);
        }

        TEST_METHOD(getProcessTokenHandleWithUserName__pname_uname)
        {
            // existing process, existing user
            wchar_t wchaUserName[MAX_PATH] = { 0 };
            DWORD dwLen = 0;
            ::GetUserName(wchaUserName, &dwLen);
            HANDLE h = process::getProcessTokenHandleWithUserName(L"explorer.exe", &std::wstring(wchaUserName));
            Assert::AreNotEqual((void*)0, (void*)h);
            ::CloseHandle(h);
        }

        TEST_METHOD(getProcessTokenHandleWithUserName__pname_invaliduname)
        {
            // existing process, non-existing user
            wchar_t wchaUserName[MAX_PATH] = { 0 };
            DWORD dwLen = 0;
            ::GetUserName(wchaUserName, &dwLen);
            wchaUserName[0] = L'-';
            HANDLE h = process::getProcessTokenHandleWithUserName(L"explorer.exe", &std::wstring(wchaUserName));
            Assert::AreEqual((void*)0, (void*)h);
            ::CloseHandle(h);
        }

        TEST_METHOD(getProcessTokenHandleWithUserName__invapname_invauname)
        {
            // invalid process, invalid user
            wchar_t wchaUserName[MAX_PATH] = { 0 };
            DWORD dwLen = 0;
            ::GetUserName(wchaUserName, &dwLen);
            wchaUserName[0] = L'-';
            HANDLE h = process::getProcessTokenHandleWithUserName(L"explorer.exe.none", &std::wstring(wchaUserName));
            Assert::AreEqual((void*)0, (void*)h);
            ::CloseHandle(h);

        }
    };
}
