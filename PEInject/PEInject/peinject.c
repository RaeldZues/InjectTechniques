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

/// <summary>
/// Start command prompt
/// TODO: Update validation checks if you plan to use this for prod.
/// </summary>
/// <param name=""></param>
/// <returns></returns>
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
	return TRUE;
}

/// <summary>
/// Get the NT Header of the image based on its base address
/// ref: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf
/// </summary>
/// <param name="imageBase">Image base address from getmodulehandle func call</param>
/// <returns>the pointer to the ntHeader of a module provided</returns>
PIMAGE_NT_HEADERS GetNtHeader(PVOID imageBase)
{
	PIMAGE_DOS_HEADER dosHeader = NULL;
	if (imageBase == NULL)
	{
		return NULL; 
	}
	dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
	return ntHeader; 
}

/// <summary>
/// Create space with proper permissions and then copy image into it 
/// </summary>
/// <param name="ntHeader"></param>
/// <returns></returns>
PVOID GetLocalImage(PVOID imageBase, PIMAGE_NT_HEADERS ntHeader)
{
	if (imageBase == NULL)
	{
		return NULL; 
	}
	// ALlocate full priv set of mem for my local image copy 
	PVOID pLocalImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// Simple error checking for now
	if (pLocalImage == NULL)
		return NULL; 
	CopyMemory(pLocalImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);
	return pLocalImage;
}


DWORD main()
{

}