#include <Windows.h>
#include <TlHelp32.h>


/// <summary>
/// Helper method to find the process ID of procName
/// </summary>
/// <param name="procName">wchar_t array of process name</param>
/// <returns>DWORD of the PID to inject into</returns>
static DWORD GetProcId(const WCHAR* procName)
{
	DWORD procId = 0;
	// Iterate through snapshot of processes to find the name of my proc
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32FirstW(hSnap, &procEntry))
		{
			do
			{
				if (!_wcsicmp(procEntry.szExeFile, procName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}


BOOL CommandStart(VOID)
{
	STARTUPINFO startInfo;
	PROCESS_INFORMATION procInfo;

	ZeroMemory(&startInfo, sizeof(STARTUPINFO));
	startInfo.cb = sizeof(STARTUPINFO);
	ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

	CreateProcessW(
		L"C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startInfo,
		&procInfo
	);

	WaitForSingleObject(procInfo.hProcess, INFINITE);
	printf("Spawning\n");
	CloseHandle(procInfo.hProcess);
	CloseHandle(procInfo.hThread);
}

DWORD main()
{

}