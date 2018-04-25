#include <stdio.h>
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
        MessageBoxA(NULL, "Process/thread attach\n", "DLL", MB_OK);
        break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
        MessageBoxA(NULL, "Process/thread detach\n", "DLL", MB_OK);
		break;
	}
	return TRUE;
}
