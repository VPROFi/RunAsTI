#include <iostream>
#include <string>
#include <system_error>
#include <codecvt>
#include <Windows.h>
#include <userenv.h>
#include <Shlobj.h>
#include <shlwapi.h>
#include <TlHelp32.h>

#pragma comment(lib,"Userenv.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Shell32.lib")

using namespace std;

#define FNERROR(prefix) GetLastErrorAsString(__FUNCTION__, prefix)
static void GetLastErrorAsString(const string fnk, const wstring prefix)
{
    DWORD errorMessageID = GetLastError();

	wcout << wstring(fnk.begin(), fnk.end()) << L"()->" << prefix << L" failed ("+to_wstring(errorMessageID)+L") ";

	LPWSTR messageBuffer = nullptr;
    if( FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
			errorMessageID,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<PWSTR>(&messageBuffer),
			0,
			nullptr) ) {
		wcout << messageBuffer;
		LocalFree(messageBuffer);
	}

	wcout << endl;
}

static bool EnablePrivilege(const wstring privilegeName)
{
	HANDLE hToken = nullptr;
	BOOL res = FALSE;

	do {
		if( !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken) ) {
			FNERROR(L"OpenProcessToken(GetCurrentProcess())");
			break;
		}

		LUID luid;
		if( !LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid) ) {
			FNERROR(L"LookupPrivilegeValueW('"+privilegeName+L"')");
			break;
		}

		TOKEN_PRIVILEGES tp = {0};
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if( !(res = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) ) {
			FNERROR(L"AdjustTokenPrivileges('"+privilegeName+L"')");
			break;
		}

	} while( false );

	if( hToken == nullptr )
		CloseHandle(hToken);

	return res;
}

static bool ImpersonateToProcess( const wstring processName )
{
	HANDLE hSnapshot = nullptr;
	HANDLE hSystemProcess = nullptr, hSystemToken = nullptr, hDupToken = nullptr;
	BOOL res = FALSE;

	do {

		if( (hSnapshot = CreateToolhelp32Snapshot(
							TH32CS_SNAPPROCESS,
							0)) == INVALID_HANDLE_VALUE ) {
			FNERROR(L"CreateToolhelp32Snapshot()");
			break;
		}

		PROCESSENTRY32W pe = {0};
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if( Process32FirstW(hSnapshot, &pe) )
			while( Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, processName.c_str()) );
		else {
			FNERROR(L"Process32FirstW('"+ processName+ L"')");
			break;
		}

		if( _wcsicmp(pe.szExeFile, processName.c_str()) ) {
			FNERROR(L"Cant`t found process: "+ processName);
			break;
		}

		if( (hSystemProcess = OpenProcess(
								PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
								FALSE,
								pe.th32ProcessID)) == nullptr) {
			FNERROR(L"OpenProcess('"+ processName+ L"')");
			break;
		}

		if( !OpenProcessToken(
				hSystemProcess,
				MAXIMUM_ALLOWED,
			&hSystemToken))	{
			FNERROR(L"OpenProcessToken('"+ processName+ L"')");
			break;
		}

		SECURITY_ATTRIBUTES tokenAttributes;
		tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		tokenAttributes.lpSecurityDescriptor = nullptr;
		tokenAttributes.bInheritHandle = FALSE;
		if( !DuplicateTokenEx(
			hSystemToken,
			MAXIMUM_ALLOWED,
			&tokenAttributes,
			SecurityImpersonation,
			TokenImpersonation,
			&hDupToken)) {
			FNERROR(L"DuplicateTokenEx('"+ processName+ L"')");
			break;
		}

		if( !(res = ImpersonateLoggedOnUser(hDupToken)) ) {
			FNERROR(L"ImpersonateLoggedOnUser('"+ processName+ L"')");
			break;
		}

	} while( false );

	if( hSystemProcess != nullptr )
		CloseHandle(hSystemProcess);

	if( hDupToken != nullptr )
		CloseHandle(hDupToken);

	if( hSnapshot != nullptr )
		CloseHandle(hSnapshot);

	return (bool)res;
}

static DWORD GetPidTrustedInstallerService()
{
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;

	do {

		if( (hSCManager = OpenSCManagerW(
							nullptr,
							SERVICES_ACTIVE_DATABASE,
							GENERIC_EXECUTE)) == nullptr) {
			FNERROR(L"OpenSCManagerW()");
			break;
		}

		if( (hService = OpenServiceW(
							hSCManager,
							L"TrustedInstaller",
							GENERIC_READ | GENERIC_EXECUTE)) == nullptr) {
			FNERROR(L"OpenServiceW('TrustedInstaller')");
			break;
		}

		SERVICE_STATUS_PROCESS statusBuffer = {0};
		DWORD bytesNeeded;
		while( 	dwProcessId == 0 &&
				started && 
				(res = QueryServiceStatusEx(
						hService,
						SC_STATUS_PROCESS_INFO,
						reinterpret_cast<LPBYTE>(&statusBuffer),
						sizeof(SERVICE_STATUS_PROCESS),
						&bytesNeeded)) ) {

			switch( statusBuffer.dwCurrentState ) {
				case SERVICE_STOPPED:
					started = StartServiceW(hService, 0, nullptr);
					if( !started ) {
						FNERROR(L"StartServiceW('TrustedInstaller'");
					}
					break;
				case SERVICE_START_PENDING:
				case SERVICE_STOP_PENDING:
					Sleep(statusBuffer.dwWaitHint);
					break;
				case SERVICE_RUNNING:
					dwProcessId = statusBuffer.dwProcessId;
					break;
			}
		}

		if( !res ) {
			FNERROR(L"QueryServiceStatusEx('TrustedInstaller')");
		}

	} while( false );

	if( hService != nullptr )
		CloseServiceHandle(hService);

	if( hSCManager != nullptr )
		CloseServiceHandle(hSCManager);

	return dwProcessId;
}

static bool CreateProcessAsTrustedInstaller(LPWSTR cmd)
{
	if( !EnablePrivilege(SE_DEBUG_NAME) ||
		!EnablePrivilege(SE_IMPERSONATE_NAME) ||
		!ImpersonateToProcess(L"winlogon.exe") )
		return false;

	HANDLE hTIProcess = nullptr, hTIToken = nullptr, hDupToken = nullptr;
    HANDLE hToken = nullptr;
    LPVOID lpEnvironment = nullptr;
	LPWSTR lpBuffer = nullptr;
	BOOL res = FALSE;

	do {

		DWORD pid = GetPidTrustedInstallerService();
		if( !pid )
			break;

		if( (hTIProcess = OpenProcess( PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid)) == nullptr ) {
			FNERROR(L"OpenProcess('TrustedInstaller')");
			break;
		}

		if( !OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken) ) {
			FNERROR(L"OpenProcessToken('TrustedInstaller')");
			break;
		}

		SECURITY_ATTRIBUTES tokenAttributes;
		tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
		tokenAttributes.lpSecurityDescriptor = nullptr;
		tokenAttributes.bInheritHandle = FALSE;
		if (!DuplicateTokenEx(
				hTIToken,
				MAXIMUM_ALLOWED,
				&tokenAttributes,
				SecurityImpersonation,
				TokenImpersonation,
				&hDupToken)) {
			FNERROR(L"DuplicateTokenEx()");
			break;
		}

		if( !OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken)) {
			FNERROR(L"OpenProcessToken(GetCurrentProcess())");
			break;
		}

		if( !CreateEnvironmentBlock(
				&lpEnvironment,
				hToken,
				TRUE)) {
			FNERROR(L"CreateEnvironmentBlock()");
			break;
		}

		DWORD nBufferLength = GetCurrentDirectoryW(0, nullptr);
		if( !nBufferLength )
			break;

		lpBuffer = (LPWSTR)(new wchar_t[nBufferLength]{0});
		if( !GetCurrentDirectoryW(nBufferLength, lpBuffer) ) {
			FNERROR(L"GetCurrentDirectoryW()");
			break;
		}

		STARTUPINFOW startupInfo;
		ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
		startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
		PROCESS_INFORMATION processInfo;
		ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
       	res = CreateProcessWithTokenW(
				hDupToken,
				LOGON_WITH_PROFILE,
				nullptr,
				cmd,
				CREATE_UNICODE_ENVIRONMENT,
				lpEnvironment,
				lpBuffer,
				&startupInfo,
				&processInfo);
		if( !res ) {
			FNERROR(wstring(L"CreateProcessWithTokenW('")+cmd+L"')");
		}

	} while(false);

	if( lpBuffer == nullptr )
		delete lpBuffer;

	if( lpEnvironment == nullptr )
		DestroyEnvironmentBlock(lpEnvironment);

	if( hToken == nullptr )
		CloseHandle(hToken);

	if( hDupToken == nullptr )
		CloseHandle(hDupToken);

	if( hTIToken == nullptr )
		CloseHandle(hTIToken);

	if( hTIProcess == nullptr )
		CloseHandle(hTIProcess);

	return (bool)res;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_CTYPE, "");

	if( !IsUserAnAdmin() ) {

		wcout << L"Error: User is not admin." << endl;

		// wait in console for gui mode
		DWORD processList = 0;
		if( GetConsoleProcessList(&processList, 1) == 1 )
			Sleep(5000);

		return 0;
	}

	try {

		if(argc == 1)
			CreateProcessAsTrustedInstaller((LPWSTR)L"cmd.exe");
		else
			CreateProcessAsTrustedInstaller((LPWSTR)PathGetArgsW(GetCommandLineW()));

	} catch (exception excpt) {
		wcout << excpt.what() << endl;
	}

	return 1;
}
