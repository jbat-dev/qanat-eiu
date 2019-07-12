#include "pch.h"
#include "CppUnitTest.h"

#include <iostream>
#include <string>
#include <windows.h>

#include "..\exec_in_usersession\exec_in_usersession.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest1_namespace
{
    TEST_CLASS(UnitTest1_class)
    {
    public:
        
        TEST_METHOD(dummyTest)
        {
            Assert::AreEqual(99, process::test(99));
        }
        TEST_METHOD(getProcessId)
        {
            Assert::AreNotEqual((DWORD)0, process::getProcessId(L"explorer.exe"));
            Assert::AreEqual((DWORD)0, process::getProcessId(L"nothing"));
        }
        TEST_METHOD(getProcessTokenHandleWithUserName)
        {
            HANDLE h = process::getProcessHandleWithUserName(L"explorer.exe");
            Assert::AreNotEqual((void*)0, (void*)h);
            ::CloseHandle(h);
        }
    };
}
