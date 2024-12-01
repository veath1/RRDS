#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")

#include <windows.h>
#include "detours.h"
#include <stdio.h>
#include <shlwapi.h>

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

// Function to resolve relative paths to full paths
void ResolveFullPath(LPCWSTR relativePath, LPWSTR fullPath, DWORD fullPathSize) {
    if (PathIsRelativeW(relativePath)) {
        GetFullPathNameW(relativePath, fullPathSize, fullPath, NULL);
    }
    else {
        wcsncpy_s(fullPath, fullPathSize, relativePath, _TRUNCATE);
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

    // Log the file access attempt
    wprintf(L"[ZwOpenFile Hook] File Name: %ls, Full Path: %ls, Desired Access: 0x%08X\n",
        fileName, fullPath, DesiredAccess);

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

    // Log the file creation attempt
    wprintf(L"[NtCreateFile Hook] File Name: %ls, Full Path: %ls, Desired Access: 0x%08X\n",
        fileName, fullPath, DesiredAccess);

    // Call the original NtCreateFile
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    LONG error;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
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

        if (error == NO_ERROR) {
            OutputDebugString(TEXT("Hooks Attached Successfully\n"));
        }
        else {
            OutputDebugString(TEXT("Hook Attachment Failed\n"));
        }

        break;
    case DLL_PROCESS_DETACH:
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
