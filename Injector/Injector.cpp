#include <stdio.h>
#include <Windows.h>

#define DLL_NAME "C:\\Users\\vp\\Documents\\visual studio 2015\\Projects\\DLLInjection\\Debug\\Lib.dll"
#define VICTIM_EXE "C:\\Windows\\System32\\Notepad.exe"

#define MODE 0

PVOID getRoutineAddr(const char *moduleName, const char *name)
{
    HMODULE hModule = GetModuleHandleA(moduleName);

    return GetProcAddress(hModule, name);
}

int main()
{
    PVOID pLoadLibraryA = getRoutineAddr("kernel32.dll", "LoadLibraryA");
    printf("LoadLibraryA address is 0x%p\n", pLoadLibraryA);

#if (MODE == 1) // Check loading into self
    HMODULE hModule = LoadLibraryA(DLL_NAME);
    printf("%s was loaded at 0x%p\n", DLL_NAME, hModule);
#elif (MODE == 2) // Check loading into self by CreateThread
    DWORD threadId;
    HANDLE hThread = CreateThread(0, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA,
        DLL_NAME, 0, &threadId);
    WaitForSingleObject(hThread, INFINITE);
#else
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    BOOL ret;
    SIZE_T bytesWritten;
    PVOID pRemoteDllName;
    DWORD remoteThreadId;
    HANDLE hRemoteThread;
    
    ret = CreateProcessA(VICTIM_EXE, NULL, NULL, NULL, FALSE, 0, NULL, NULL,
        (LPSTARTUPINFOA)&si, &pi);
    if (!ret)
    {
        fprintf(stderr, "CreateProcess failed with %d\n", GetLastError());
        return -1;
    }
    printf("Child process 0x%p with PID %d was created\n", pi.hProcess, pi.dwProcessId);

    pRemoteDllName = VirtualAllocEx(pi.hProcess, NULL, sizeof(DLL_NAME),
        MEM_COMMIT, PAGE_READWRITE);
    fprintf(stderr, "Dll name at 0x%p in remote process\n", pRemoteDllName);
    if (!pRemoteDllName)
    {
        return -1;
    }

    ret = WriteProcessMemory(pi.hProcess, pRemoteDllName, DLL_NAME,
        sizeof(DLL_NAME), &bytesWritten);
    printf("bytesWritten = %zu\n", bytesWritten);

    hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteDllName, 0, &remoteThreadId);
    printf("Remote thread 0x%p with TID %d\n", hRemoteThread, remoteThreadId);

    WaitForSingleObject(pi.hProcess, INFINITE);
#endif
    

    return 0;
}
