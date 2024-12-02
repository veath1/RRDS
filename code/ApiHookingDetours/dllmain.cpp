#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")

#include <windows.h>
#include "detours.h"
#include <stdio.h>
#include <shlwapi.h>
#include <unordered_map>
#include <vector>
#include <string>

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

// Define the prototype for ZwOpenFile
typedef NTSTATUS(WINAPI* ZwOpenFile_t)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
    );

typedef NTSTATUS(WINAPI* NtCreateFile_t)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

// Pointers to the original functions
ZwOpenFile_t Real_ZwOpenFile = NULL;
NtCreateFile_t Real_NtCreateFile = NULL;


NTSTATUS WINAPI Hooked_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

NTSTATUS WINAPI Hooked_ZwOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

// Global map to store remaining substrings and their occurrences
std::unordered_map<std::wstring, int> remaining_map;
std::wstring previous_fullPath;

// Global vector to track backup files
std::vector<std::pair<std::wstring, std::wstring>> backup_files;

// Function to resolve relative paths to full paths
void ResolveFullPath(LPCWSTR relativePath, LPWSTR fullPath, DWORD fullPathSize) {
    if (PathIsRelativeW(relativePath)) {
        GetFullPathNameW(relativePath, fullPathSize, fullPath, NULL);
    }
    else {
        wcsncpy_s(fullPath, fullPathSize, relativePath, _TRUNCATE);
    }
}

// Function to find and extract the remaining substring
std::wstring extract_remaining(const std::wstring& str1, const std::wstring& str2) {
    const std::wstring* shorter;
    const std::wstring* longer;

    if (str1.length() < str2.length()) {
        shorter = &str1;
        longer = &str2;
    }
    else {
        return L"";
    }

    size_t pos = longer->find(*shorter);
    if (pos == std::wstring::npos) {
        return L"";
    }

    return longer->substr(0, pos) + longer->substr(pos + shorter->length());
}

LONG InstallHook() {

    LONG error;
    // Attach the hooks
    OutputDebugString(TEXT("Attaching ZwOpenFile and NtCreateFile Hooks\n"));
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Get the address of ZwOpenFile and NtCreateFile from ntdll.dll
    Real_ZwOpenFile = (ZwOpenFile_t)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwOpenFile");
    Real_NtCreateFile = (NtCreateFile_t)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateFile");

    if (Real_ZwOpenFile) {
        DetourAttach(&(PVOID&)Real_ZwOpenFile, Hooked_ZwOpenFile);
    }
    if (Real_NtCreateFile) {
        DetourAttach(&(PVOID&)Real_NtCreateFile, Hooked_NtCreateFile);
    }

    error = DetourTransactionCommit();
    return error;

}

LONG RemoveHook() {

    LONG error;
    // Detach the hooks
    OutputDebugString(TEXT("Detaching ZwOpenFile and NtCreateFile Hooks\n"));
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (Real_ZwOpenFile) {
        DetourDetach(&(PVOID&)Real_ZwOpenFile, Hooked_ZwOpenFile);
    }
    if (Real_NtCreateFile) {
        DetourDetach(&(PVOID&)Real_NtCreateFile, Hooked_NtCreateFile);
    }

    error = DetourTransactionCommit();
    return error;
}


// Function to detect ransomware and handle backups
void detect_ransomware(const std::wstring& path1, const std::wstring& path2) {
    std::wstring remaining = extract_remaining(path1, path2);

    if (!remaining.empty()) {
        remaining_map[remaining]++;

        // Prepare the backup
        std::wstring tempPath = L"C:\\temp\\" + std::wstring(PathFindFileNameW(path1.c_str()));

        backup_files.emplace_back(path1, tempPath);
        wprintf(L"Backed up: %ls to %ls\n", path1.c_str(), tempPath.c_str());

        if (remaining_map[remaining] >= 3) {

            RemoveHook();
            wprintf(L"Potential ransomware pattern detected: %ls\n", remaining.c_str());

            // Restore backed-up files
            for (const auto& backup : backup_files) {
                const auto& originalPath = backup.first;
                const auto& tempPath = backup.second;

                if (CopyFileW(tempPath.c_str(), originalPath.c_str(), FALSE)) {
                    wprintf(L"Restored: %ls to %ls\n", tempPath.c_str(), originalPath.c_str());
                    //DeleteFileW(tempPath.c_str());
                }
                else {
                    wprintf(L"Failed to restore: %ls\n", tempPath.c_str());
                }
            }

            // Exit process to simulate protection (can be removed for testing)
            ExitProcess(0);
        }

       
    
        
        
      

    }
}

// Function to remove the \??\ prefix
void RemovePrefix(LPWSTR fullPath) {
    const WCHAR prefix[] = L"\\??\\";
    size_t prefix_len = wcslen(prefix);
    size_t fullPath_len = wcslen(fullPath);

    if (fullPath_len >= prefix_len && wcsncmp(fullPath, prefix, prefix_len) == 0) {
        memmove(fullPath, fullPath + prefix_len, (fullPath_len - prefix_len + 1) * sizeof(WCHAR));
    }
}

// Hooked ZwOpenFile function
NTSTATUS WINAPI Hooked_ZwOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
) {

    
    WCHAR fileName[MAX_PATH] = L"[Unknown]";
    WCHAR fullPath[MAX_PATH] = L"[Unknown]";

    // Try to retrieve the file name if possible
    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        wcsncpy_s(fileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR));
        ResolveFullPath(fileName, fullPath, MAX_PATH);
    }

    // Remove the \\??\\ prefix
    RemovePrefix(fullPath);


    RemoveHook();
    // Prepare the backup
    std::wstring tempPath = L"C:\\temp\\" + std::wstring(PathFindFileNameW(fullPath));
    if (CopyFileW(fullPath, tempPath.c_str(), FALSE)) {
        wprintf(L"Backed up: %ls to %ls\n", fullPath, tempPath.c_str());
    }
    else {
        wprintf(L"Failed to back up: %ls, Error: %lu\n", fullPath, GetLastError());

    }
    InstallHook();

    // Log the file access attempt
    wprintf(L"[ZwOpenFile Hook] File Name: %ls, Full Path: %ls, Desired Access: 0x%08X\n",
        fileName, fullPath, DesiredAccess);

    if (!(previous_fullPath.empty())) {
        detect_ransomware(previous_fullPath, fullPath);
    }
    previous_fullPath = fullPath;


    // Call the original ZwOpenFile
    return Real_ZwOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

// Hooked NtCreateFile function
NTSTATUS WINAPI Hooked_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {

    WCHAR fileName[MAX_PATH] = L"[Unknown]";
    WCHAR fullPath[MAX_PATH] = L"[Unknown]";

    // Try to retrieve the file name if possible
    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        wcsncpy_s(fileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR));
        ResolveFullPath(fileName, fullPath, MAX_PATH);
    }

    // Remove the \\??\\ prefix
    RemovePrefix(fullPath);

    // Log the file creation attempt
    wprintf(L"[NtCreateFile Hook] File Name: %ls, Full Path: %ls, Desired Access: 0x%08X\n",
        fileName, fullPath, DesiredAccess);

    
    // Detect ransomware pattern
    if (!(previous_fullPath.empty())) {
        detect_ransomware(previous_fullPath, fullPath);
    }
    previous_fullPath = fullPath;
   

    // Call the original NtCreateFile
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    LONG error;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:

        error = InstallHook();

        if (error == NO_ERROR) {
            OutputDebugString(TEXT("Hooks Attached Successfully\n"));
        }
        else {
            OutputDebugString(TEXT("Hook Attachment Failed\n"));
        }

        break;
    case DLL_PROCESS_DETACH:

        error = RemoveHook();
        
        if (error == NO_ERROR) {
            OutputDebugString(TEXT("Hooks Detached Successfully\n"));
        }
        else {
            OutputDebugString(TEXT("Hook Detachment Failed\n"));
        }

        break;
    }
    return TRUE;
}