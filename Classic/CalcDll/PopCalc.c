#include <Windows.h>
#include <stdio.h>

#define DllExport __declspec(dllexport)

DllExport void __stdcall PopCalc(void)
{
    // Deprecated but using for simplicity 
    WinExec("calc", 0);
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