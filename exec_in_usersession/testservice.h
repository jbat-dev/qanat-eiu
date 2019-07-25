#pragma once


namespace service {
    wchar_t SERVICE_NAME[];
    wchar_t DISPLAY_NAME[];
    void registerService();
    void unregisterService();
    VOID WINAPI serviceMain(DWORD, LPWSTR*);
}