// exec_in_usersession.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <atlbase.h>

#include "exec_in_usersession.h"


namespace {
	// プログラム名が name のプロセスの ID を返す
	DWORD getProcessId(const std::wstring& name)
	{
		DWORD dwResult = 0;
		CHandle snapshot(CreateToolhelp32Snapshot(2, 0)); // 2=TH32CS_SNAPPROCESS
		if (snapshot == INVALID_HANDLE_VALUE) {
			return dwResult;
		}

		PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
		if (!Process32First(snapshot, &entry)) {
			return dwResult;
		}

		do {
			if (wcscmp(entry.szExeFile, name.c_str()) == 0) {
				dwResult = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &entry));

		return dwResult;
	}


	// token ユーザ，env 環境変数で app プログラムを実行（引数 param）
	BOOL createProcessAsUser(const std::wstring& app, const std::wstring& param, HANDLE token, DWORD creationFlags, LPVOID env)
	{
		wchar_t arg[MAX_PATH] = L"";

		wcscpy_s(arg, (param.empty() ? app.c_str() : (app + L" " + param).c_str()));

		STARTUPINFO         si = { sizeof(STARTUPINFO), nullptr };
		si.lpDesktop = (LPWSTR)L"winsta0\\default";

		PROCESS_INFORMATION pi = {};
		const BOOL          retval = CreateProcessAsUser(token, nullptr, arg, nullptr, nullptr, FALSE, creationFlags, env, nullptr, &si, &pi);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		return retval;
	}
}


BOOL process::createProcess(const std::wstring& app, const std::wstring& param, HANDLE process)
{
	BOOL retval = FALSE;

	if (process) {
		CHandle processToken;

		// process のユーザトークン
		// CreateProcessAsUser が TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY を要求することに注意
		if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken.m_h)) {
			CHandle userToken;

			// CreateProcessAsUser のためにトークンを複製し，プライマリトークンを作成する
			if (DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &userToken.m_h)) {
                // DWORD  sessionId = WTSGetActiveConsoleSessionId();  // pedding //
                DWORD sessionId = 0;
                ProcessIdToSessionId(GetProcessId(process), &sessionId);
                DWORD  creationFlags = CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS;
				LPVOID env = nullptr;

				// アクティブユーザのセッションを設定します
				SetTokenInformation(userToken, TokenSessionId, &sessionId, sizeof(DWORD));

				// 環境変数を設定します
				if (CreateEnvironmentBlock(&env, userToken, TRUE)) {
					creationFlags |= CREATE_UNICODE_ENVIRONMENT;
				}
				else {
					env = nullptr;
				}

				retval = createProcessAsUser(app, param, userToken, creationFlags, env);

				DestroyEnvironmentBlock(env);
			}
		}
	}
	else { 
		CHandle target(OpenProcess(MAXIMUM_ALLOWED, FALSE, getProcessId(L"explorer.exe")));
		if (target) {
			return createProcess(app, param, target);
		}
	}

	return retval;
}


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
	std::wcout << L"app=" + wstrExeName + L"\n";
	std::wcout << L"arg=" + wstrExeArg + L"\n";

	return process::createProcess(wstrExeName, wstrExeArg);
}

