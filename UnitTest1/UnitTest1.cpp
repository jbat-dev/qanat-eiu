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
		
		TEST_METHOD(TestMethod1)
		{
            Assert::AreEqual(99, process::test(99));
		}
	};
}
