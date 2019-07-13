
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <atlbase.h>

#include <string>
#include <windows.h>

#include "exec_in_usersession.h"

namespace service {
    wchar_t SERVICE_NAME[] = L"TestService";
    wchar_t DISPLAY_NAME[] = L"テストサービス2";


    // get app path
    const std::wstring getAppPath(HINSTANCE instance = nullptr)
    {
        wchar_t path[MAX_PATH] = L"";

        GetModuleFileName(instance, path, MAX_PATH);

        return std::wstring(path);
    }

    // regist service
    void registerService()
    {
        if (SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)) {
            if (SC_HANDLE service = CreateService(scManager, SERVICE_NAME, DISPLAY_NAME,
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL, (getAppPath() + L" --start").c_str(), nullptr, 0, nullptr, nullptr, nullptr)) {

                StartService(service, 0, nullptr);

                CloseServiceHandle(service);
            }

            CloseServiceHandle(scManager);
        }
    }


    // unregist service
    void unregisterService()
    {
        if (SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT)) {
            if (SC_HANDLE service = OpenService(scManager, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)) {
                SERVICE_STATUS ss;

                QueryServiceStatus(service, &ss);
                if (ss.dwCurrentState == SERVICE_RUNNING) { // もし実行中なら
                    ControlService(service, SERVICE_CONTROL_STOP, &ss); // 終了する
                }

                DeleteService(service);
                CloseServiceHandle(service);
            }

            CloseServiceHandle(scManager);
        }
    }


    HANDLE                gStopEvent = nullptr;
    SERVICE_STATUS        gServiceStatus = {};
    SERVICE_STATUS_HANDLE gServiceHandle = nullptr;


    DWORD WINAPI handlerEx(DWORD control, DWORD, LPVOID, LPVOID)
    {
        switch (control) {
        case SERVICE_CONTROL_STOP: // 終了要求
            gServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            gServiceStatus.dwCheckPoint = 0;
            gServiceStatus.dwWaitHint = 2000;

            SetServiceStatus(gServiceHandle, &gServiceStatus);
            SetEvent(gStopEvent);

            break;
        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(gServiceHandle, &gServiceStatus);

            break;
        }

        return NO_ERROR;
    }


    VOID WINAPI serviceMain(DWORD, LPWSTR*)
    {
        gStopEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        gServiceHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, &handlerEx, nullptr);

        gServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        gServiceStatus.dwCurrentState = SERVICE_RUNNING;
        gServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        gServiceStatus.dwWin32ExitCode = NO_ERROR;
        gServiceStatus.dwServiceSpecificExitCode = 0;
        gServiceStatus.dwCheckPoint = 0;
        gServiceStatus.dwWaitHint = 0;

        SetServiceStatus(gServiceHandle, &gServiceStatus);

        fout.open(L"c:\\temp\\log2.txt", std::ios::app);
        fout << "test" << std::endl;

        // start service
        { 
            ::WinExec("C:\\Users\\J32330\\source\\repos\\thabara\\exec_in_usersession3\\x64\\Debug\\exec_in_usersession.exe c:\\windows\\notepad.exe \"\" J35021", SW_NORMAL);
        }

        ::Sleep(3000);

        // and stop soon
        { // 終了処理
            CloseHandle(gStopEvent);
            gServiceStatus.dwCurrentState = SERVICE_STOPPED;
            gServiceStatus.dwCheckPoint = 0;
            gServiceStatus.dwWaitHint = 0;

            SetServiceStatus(gServiceHandle, &gServiceStatus);
        }

        fout << std::endl;
        fout << std::endl;
        fout.close();

    }
}

