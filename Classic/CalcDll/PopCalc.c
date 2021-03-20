#include <Windows.h>
#include <stdio.h>

#define DllExport __declspec(dllexport)

DllExport void __stdcall PopCalc(void)
{
	STARTUPINFO startInfo;
	PROCESS_INFORMATION procInfo;

	ZeroMemory(&startInfo, sizeof(STARTUPINFO));
	startInfo.cb = sizeof(STARTUPINFO);
	ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));


	CreateProcess(
		"C:\\Windows\\System32\\calc.exe",
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


BOOL WINAPI DllMain(
    HINSTANCE hinstDll,
    DWORD fdwReason,
    LPVOID lpReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        PopCalc(); 
        break; 
    case DLL_THREAD_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}