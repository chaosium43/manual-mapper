// injector.h: Top level header file for injector executable

#include <windows.h>
#include <psapi.h>
#include <pthread.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <bits/stdc++.h>

// shellcode related structs
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR dllName);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE dllBase, LPCSTR procName);
typedef BOOL (WINAPI *pDllMain)(HMODULE dllBase, DWORD dwReason, LPVOID thing);
typedef BOOLEAN (WINAPIV *pRtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
typedef struct {
    UINT EnableTLS : 1; // enabling this causes TLS callbacks to be done on DLL inject
    UINT EnableSEH : 1; // enabling this causes SEH to be initialized on DLL inject
    UINT FixProtections : 1; // this sets the pages to the correct protections instead of sussy PAGE_EXECUTE_READWRITE
    UINT EraseHeader : 1; // this will fill the PE header with junk when set to 1
    UINT HijackThread : 1; // currently does nothing, in future will enable thread hijacking to run DllMain instead of normal CreateRemoteThread
    UINT ExternalFixup : 1; // currently does nothing, in future will enable the resolving of imports and relocations externally if turned on
    UINT unused : 2;
} INJECTCONFIG;
typedef struct {
    HMODULE dllBase;
    pLoadLibraryA LoadLibraryA;
    pGetProcAddress GetProcAddress;
    pRtlAddFunctionTable RtlAddFunctionTable;
    IMAGE_OPTIONAL_HEADER optHeader;
    INJECTCONFIG config;
} SHELLCODEPARAMS;
typedef struct {
    WORD offset : 12;
    WORD type : 4;
} RELOCATION_INFO;

// not part of the core library but used to make testing more convenient
HANDLE getProcessHandle(DWORD dwPid);
DWORD getProcessId(LPCSTR procName);
BOOL WINAPI Inject(LPCSTR procName, std::string dllPath, INJECTCONFIG config);

// functions for interfacing with external processes
extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE hProcess, LPVOID pBaseAddress, LPVOID pBuffer, SIZE_T bytesToWrite, PSIZE_T pBytesWritten);
extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE hProcess, LPVOID pBaseAddress, LPVOID pBuffer, SIZE_T bytesToRead, PSIZE_T bytesRead);
extern "C" NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE hProcess, LPVOID pBaseAddress, PULONG pBytesToProtect, ULONG newProtect, PULONG pOldProtect);
LPVOID ManualMap(HANDLE hProcess, std::string dllPath, INJECTCONFIG config);
LPVOID ManualMap(HANDLE hProcess, std::string dllPath);
LPVOID DebugMap(std::string dllPath, INJECTCONFIG config); // does internal DLL inject so that shellcode can be debugged for issues
DWORD __stdcall Shellcode(SHELLCODEPARAMS* params); // resolves imports internally within a process