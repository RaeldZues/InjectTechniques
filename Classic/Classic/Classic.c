#include <Windows.h>
#include <Memoryapi.h>
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


/// <summary>
/// Classic dll injection into notepad.exe 
/// 1. Open a proc 
/// 2. Allocate space into process remotely 
/// 3. Write dll into process space memory 
/// 4. Create remote thread 
/// 5. Cleanup 
/// </summary>
/// <returns></returns>
DWORD main()
{
    wchar_t calcdll[] = L"..\CalcDll.dll";
	wchar_t notepad[] = L"notepad.exe";
    HANDLE remoteProcHandle = INVALID_HANDLE_VALUE; 
    PVOID remoteProcBuffer = NULL; 
	DWORD PID = GetProcId(notepad);
	// Quick out if I couldnt get the pid properly 
	if (PID < 1)
		return PID; 
	// Step 1
	remoteProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (remoteProcHandle == INVALID_HANDLE_VALUE)
		return -1; 
	// Step 2
	remoteProcBuffer = VirtualAllocEx(remoteProcHandle, NULL, sizeof(calcdll), MEM_COMMIT, PAGE_READWRITE);
	if (remoteProcBuffer == NULL)
	{
		CloseHandle(remoteProcHandle);
		return -1; 
	}
	

	return 8675309;
}