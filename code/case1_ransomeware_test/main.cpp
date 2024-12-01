#include <stdio.h>
#include <wchar.h>
#include <windows.h>

int wmain() {
    const wchar_t* originalFilePath = L"cat.jpg";
    wchar_t newFilePath[MAX_PATH];

    // Append ".bbawasted" to the original file path
    wcscpy(newFilePath, originalFilePath);
    wcscat(newFilePath, L".bbawasted");

    // Wait for user input before proceeding
    wprintf(L"Press Enter to start the program...\n");
    getchar();

    // Rename the file
    if (MoveFileW(originalFilePath, newFilePath) == 0) {
        wprintf(L"Failed to rename file. Error: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"File renamed successfully from '%ls' to '%ls'.\n", originalFilePath, newFilePath);

    // Open the renamed file for reading
    HANDLE hFile = CreateFileW(newFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file. Error: %lu\n", GetLastError());
        return 1;
    }

    // Read the first 16 bytes of the file
    BYTE buffer[16];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
        wprintf(L"Failed to read file. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    wprintf(L"First 16 bytes of the file:\n");
    for (DWORD i = 0; i < bytesRead; i++) {
        wprintf(L"%02X ", buffer[i]);
    }
    wprintf(L"\n");

    // Close the file handle
    CloseHandle(hFile);

    return 0;
}
