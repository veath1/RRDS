#include <stdio.h>
#include <wchar.h>
#include <windows.h>

// Function to rename and read file
void renameAndReadFile(const wchar_t* originalFilePath) {
    wchar_t newFilePath[MAX_PATH];

    // Append ".bbawasted" to the original file path
    wcscpy(newFilePath, originalFilePath);
    wcscat(newFilePath, L".bbawasted");

    // Rename the file
    if (MoveFileW(originalFilePath, newFilePath) == 0) {
        wprintf(L"Failed to rename file. Error: %lu\n", GetLastError());
        return;
    }

    wprintf(L"File renamed successfully from '%ls' to '%ls'.\n", originalFilePath, newFilePath);

    // Open the renamed file for reading
    HANDLE hFile = CreateFileW(newFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file. Error: %lu\n", GetLastError());
        return;
    }

    // Read the first 16 bytes of the file
    BYTE buffer[16];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
        wprintf(L"Failed to read file. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    wprintf(L"First 16 bytes of the file:\n");
    for (DWORD i = 0; i < bytesRead; i++) {
        wprintf(L"%02X ", buffer[i]);
    }
    wprintf(L"\n");

    // Overwrite the first 16 bytes with zeroes
    if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        wprintf(L"Failed to rewind file pointer. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    BYTE zeroBuffer[16] = { 0 };
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, zeroBuffer, sizeof(zeroBuffer), &bytesWritten, NULL)) {
        wprintf(L"Failed to overwrite file. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }
    wprintf(L"Overwrote first %lu bytes with zero.\n", bytesWritten);

    // Close the file handle
    CloseHandle(hFile);
}

int wmain(int argc, wchar_t* argv[]) {
    
    // Wait for user input before proceeding
    wprintf(L"Press Enter to start the program...\n");
    getchar();

    // Call the function with the provided file path
    renameAndReadFile(L"cat.jpg");
    renameAndReadFile(L"dog.jpg");
    renameAndReadFile(L"meow.jpg");

    return 0;
}
