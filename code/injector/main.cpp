#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    HANDLE processHandle;
    PVOID remoteBuffer;

    wchar_t dllPath[] = TEXT("ApiHookingDetours.dll");
    wchar_t exePath[] = TEXT("case1_ransomeware_test.exe");

    //tmp file setting
    CopyFileW(L"tmp_cat.jpg", L"cat.jpg", FALSE);
    DeleteFileW(L"cat.jpg.bbawasted");


    // Structures required to create a process
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    si.cb = sizeof(STARTUPINFO);

    // Create the target process
    if (!CreateProcessW(
        exePath,              // Program path
        NULL,           // Command-line arguments
        NULL,              // Process security attributes
        NULL,              // Thread security attributes
        FALSE,             // Whether handles are inherited
        0,                 // Creation flags
        NULL,              // Environment variables
        NULL,              // Current directory
        &si,               // STARTUPINFO
        &pi                // PROCESS_INFORMATION
    )) {
        printf("Failed to create process. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("Successfully started process. PID: %lu\n", pi.dwProcessId);

    // Start DLL injection
    printf("Injecting DLL to PID: %lu\n", pi.dwProcessId);
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

    if (processHandle == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        return 1;
    }

    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        CloseHandle(processHandle);
        return 1;
    }

    if (!WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL)) {
        printf("Failed to write to process memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
    if (threatStartRoutineAddress == NULL) {
        printf("Failed to get LoadLibraryW address. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
    if (remoteThread == NULL) {
        printf("Failed to create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    printf("DLL successfully injected.\n");

    // Clean up resources
    CloseHandle(remoteThread);
    VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(processHandle);

    // Wait for the created process to exit
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
