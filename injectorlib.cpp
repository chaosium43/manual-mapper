#include "injector.hpp"

DWORD getProcessId(LPCSTR procName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp((LPCSTR)pe32.szExeFile, procName)) {
            continue;
        }
        return pe32.th32ProcessID;
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

HANDLE getProcessHandle(DWORD dwPid) { // opens a handle to a process with a given process ID
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == INVALID_HANDLE_VALUE) { // unable to open process wompwomp
        return INVALID_HANDLE_VALUE;
    }
    return hProcess;
}

LPVOID ManualMap(HANDLE hProcess, std::string dllPath, INJECTCONFIG config) { // manually mapping a DLL into the memory of a victim process
    // reading DLL data
    std::fstream dllStream(dllPath, std::ios::in | std::ios::binary | std::ios::ate);
    if (dllStream.fail()) {
        std::cout << "Unable to open " << dllPath << std::endl;
        return NULL;
    }
    size_t dllSize = dllStream.tellg();
    char *dllBytes = new char[dllSize];
    dllStream.seekg(0, std::ios::beg);
    dllStream.read(dllBytes, dllSize);
    dllStream.close();

    // validating the DLL
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBytes);
    if ((dosHeader->e_magic) != 0x5A4D) {
        std::cout << "Invalid DLL passed (1)" << std::endl;
        delete[] dllBytes;
        return NULL;
    }
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllBytes + dosHeader->e_lfanew);
    if ((ntHeaders->Signature) != 0x4550) {
        std::cout << "Invalid DLL passed (2)" << std::endl;
        printf("0x%llx", ntHeaders->Signature);
        delete[] dllBytes;
        return NULL;
    }
    if ((ntHeaders->FileHeader.Machine) != IMAGE_FILE_MACHINE_AMD64) {
        std::cout << "Injector will only work on AMD64" << std::endl;
        delete[] dllBytes;
        return NULL;
    }
    IMAGE_OPTIONAL_HEADER optHeader = ntHeaders->OptionalHeader;

    // Allocating DLL memory in the target process
    LPVOID dllBase = VirtualAllocEx(hProcess, NULL, optHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (dllBase == NULL) {
        std::cout << "Failed to allocate memory for DLL: " << GetLastError() << std::endl;
        return NULL;
    }

    // writing DLL to memory
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i != ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        if (sectionHeader->SizeOfRawData) {
            NTSTATUS status = NtWriteVirtualMemory(hProcess, reinterpret_cast<PBYTE>(dllBase) + sectionHeader->VirtualAddress, dllBytes + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, NULL);
            if (status) {
                std::cout << "Failed to write DLL into process memory: " << status << std::endl;
                VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
                return NULL;
            }
        }
    }

    SHELLCODEPARAMS params;
    params.dllBase = reinterpret_cast<HMODULE>(dllBase);
    params.LoadLibraryA = LoadLibraryA;
    params.GetProcAddress = GetProcAddress;
    params.RtlAddFunctionTable = RtlAddFunctionTable;
    params.optHeader = optHeader;
    params.config = config;

    // writing shellcode to memory
    LPVOID shellcodeBase = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcodeBase == NULL) {
        std::cout << "Failed to allocate shellcode" << std::endl;
        VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
        delete[] dllBytes;
        return NULL;
    }
    NTSTATUS status = NtWriteVirtualMemory(hProcess, shellcodeBase, reinterpret_cast<LPVOID>(Shellcode), 0x1000, NULL);
    if (status) {
        std::cout << "Failed to write shellcode: " << status << std::endl;
        VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, shellcodeBase, 0, MEM_RELEASE);
        delete[] dllBytes;
        return NULL;
    }

    // writing parameters to memory
    LPVOID paramsBase = VirtualAllocEx(hProcess, NULL, sizeof(SHELLCODEPARAMS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (paramsBase == NULL) {
        std::cout << "Failed to allocate parameters" << std::endl;
        VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, shellcodeBase, 0, MEM_RELEASE);
        delete[] dllBytes;
        return NULL;
    }
    status = NtWriteVirtualMemory(hProcess, paramsBase, &params, sizeof(SHELLCODEPARAMS), NULL);
    if (status) {
        std::cout << "Failed to write shellcode params " << status << std::endl;
        VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, shellcodeBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, paramsBase, 0, MEM_RELEASE);
        delete[] dllBytes;
        return NULL;
    }

    // running shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeBase, paramsBase, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 42069;
    GetExitCodeThread(hThread, &exitCode);

    // cleanup
    VirtualFreeEx(hProcess, shellcodeBase, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, paramsBase, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // check that the DLL actually injected successfully
    if (exitCode) {
        switch (exitCode) {
            case 1:
                std::cout << "Unable to load DLL dependencies" << std::endl;
                break;
            case 2:
                std::cout << "Unable to resolve DLL thunks" << std::endl;
                break;
            case 3:
                std::cout << "DllMain returned FALSE" << std::endl;
                break;
            default:
                std::cout << "Unable to inject DLL: " << exitCode << std::endl;
                break;
        }
        VirtualFreeEx(hProcess, dllBase, 0, MEM_RELEASE);
        delete[] dllBytes;
        return NULL;
    }

    // re-adjusting protections to not look sus
    if (config.FixProtections) {
        sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i != ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            if (sectionHeader->Misc.VirtualSize) {
                DWORD protection = PAGE_READONLY;
                DWORD sectionProtection = sectionHeader->Characteristics;
                if (sectionProtection & IMAGE_SCN_MEM_WRITE) {
                    protection = PAGE_READWRITE;
                } else if (sectionProtection & IMAGE_SCN_MEM_EXECUTE) {
                    protection = PAGE_EXECUTE_READ;
                }
                if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>((ULONGLONG)dllBase + sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize, protection, NULL)) {
                    printf("WARNING: Unable to adjust protections for section 0x%llx\n", (ULONGLONG)dllBase + sectionHeader->VirtualAddress);
                } else {
                    printf("Successfully adjusted protections for 0x%llx\n", (ULONGLONG)dllBase + sectionHeader->VirtualAddress);
                }
            }
        }
    }

    if (config.EraseHeader) { // erase PE header
        PBYTE buffer = reinterpret_cast<PBYTE>(malloc(0x1000)); // doing a base malloc guarantees that the buffer will be filled with garbage
        status = NtWriteVirtualMemory(hProcess, dllBase, buffer, 0x1000, NULL);
        if (status) {
            printf("Unable to erase PE header: 0x%llx\n", status);
        } else {
            std::cout << "Successfully erased PE header" << std::endl;
        }
        delete[] buffer;
    }

    delete[] dllBytes;
    return dllBase;
}

LPVOID DebugMap(std::string dllPath, INJECTCONFIG config) {
    // reading DLL data
    std::fstream dllStream(dllPath, std::ios::in | std::ios::binary | std::ios::ate);
    if (dllStream.fail()) {
        std::cout << "Unable to open " << dllPath << std::endl;
        return NULL;
    }
    size_t dllSize = dllStream.tellg();
    char *dllBytes = new char[dllSize];
    dllStream.seekg(0, std::ios::beg);
    dllStream.read(dllBytes, dllSize);
    dllStream.close();

    // validating the DLL
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBytes);
    if ((dosHeader->e_magic) != 0x5A4D) {
        std::cout << "Invalid DLL passed (1)" << std::endl;
        delete[] dllBytes;
        return NULL;
    }
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllBytes + dosHeader->e_lfanew);
    if ((ntHeaders->Signature) != 0x4550) {
        std::cout << "Invalid DLL passed (2)" << std::endl;
        printf("0x%llx", ntHeaders->Signature);
        delete[] dllBytes;
        return NULL;
    }
    if ((ntHeaders->FileHeader.Machine) != IMAGE_FILE_MACHINE_AMD64) {
        std::cout << "Injector will only work on AMD64" << std::endl;
        delete[] dllBytes;
        return NULL;
    }
    IMAGE_OPTIONAL_HEADER optHeader = ntHeaders->OptionalHeader;
    // Allocating DLL memory in the target process
    LPVOID dllBase = malloc(optHeader.SizeOfImage);

    // writing DLL to memory
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        if (sectionHeader->SizeOfRawData) {
            PBYTE sectionStart = reinterpret_cast<PBYTE>((ULONGLONG)dllBase + sectionHeader->VirtualAddress);
            PBYTE buffer = reinterpret_cast<PBYTE>((ULONGLONG)dllBytes + sectionHeader->PointerToRawData);
            for (int j = 0; j < (sectionHeader->SizeOfRawData); ++j) {
                sectionStart[j] = buffer[j];
            }
        }
    }

    delete[] dllBytes; // dll data buffer is no longer needed after it's been written to memory

    SHELLCODEPARAMS params;
    params.dllBase = reinterpret_cast<HMODULE>(dllBase);
    params.LoadLibraryA = LoadLibraryA;
    params.GetProcAddress = GetProcAddress;
    params.RtlAddFunctionTable = RtlAddFunctionTable;
    params.optHeader = optHeader;
    params.config = config;
    printf("0x%llx\n", optHeader.AddressOfEntryPoint);
    Shellcode(&params);

    return dllBase;
}


DWORD __stdcall Shellcode(SHELLCODEPARAMS* params) {
    // loading up params for future use
    HMODULE dllBase = params->dllBase;
    pLoadLibraryA _LoadLibraryA = params->LoadLibraryA;
    pGetProcAddress _GetProcAddress = params->GetProcAddress;
    pRtlAddFunctionTable _RtlAddFunctionTable = params->RtlAddFunctionTable;
    IMAGE_OPTIONAL_HEADER optHeader = params->optHeader;
    INJECTCONFIG config = params->config;
    
    // fixing relocations
    UINT_PTR relocOffset = (UINT_PTR)((ULONGLONG)dllBase - optHeader.ImageBase);
    if (relocOffset != 0) {
        PIMAGE_BASE_RELOCATION relocBase = reinterpret_cast<PIMAGE_BASE_RELOCATION>((ULONGLONG)dllBase + (ULONGLONG)optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD va = relocBase->VirtualAddress;
        while (relocBase->VirtualAddress != 0) {
            UINT relocations = (relocBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCATION_INFO);
            RELOCATION_INFO *relocation = reinterpret_cast<RELOCATION_INFO*>(relocBase + 1);
            for (UINT i = 0; i < relocations; ++i, ++relocation) {
                if ((relocation->type) == IMAGE_REL_BASED_DIR64) {
                    UINT_PTR* addy = reinterpret_cast<UINT_PTR*>((ULONGLONG)dllBase + relocBase->VirtualAddress + relocation->offset);
                    *addy += relocOffset;
                }
            }
            relocBase = reinterpret_cast<PIMAGE_BASE_RELOCATION>((ULONGLONG)relocBase + relocBase->SizeOfBlock);
        }
    }
    //std::cout << "fixed relocations award" << std::endl;
    // fixing imports
    if (optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        IMAGE_IMPORT_DESCRIPTOR *importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>((ULONGLONG)dllBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name) {
            char *szMod = reinterpret_cast<char*>((ULONGLONG)dllBase + (importDesc->Name));
            HMODULE hDll = _LoadLibraryA(szMod);

            if (!hDll) {
                return 1;
            }
            
            PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONGLONG)dllBase + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>((ULONGLONG)dllBase + importDesc->OriginalFirstThunk);

            if (!origFirstThunk) {
                origFirstThunk = firstThunk;
            }

            while (origFirstThunk->u1.AddressOfData) {
                ULONGLONG funcAddy = 0;
                if ((origFirstThunk->u1.Ordinal) & IMAGE_ORDINAL_FLAG) { // import by ordinal
                    funcAddy = (ULONGLONG)_GetProcAddress(hDll, (LPCSTR)((origFirstThunk->u1.Ordinal) & 0xFFFF));
                } else { // import by name
                    PIMAGE_IMPORT_BY_NAME pIBN = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((ULONGLONG)dllBase + origFirstThunk->u1.AddressOfData);
                    funcAddy = (ULONGLONG)_GetProcAddress(hDll, (LPCSTR)pIBN->Name);
                }
                if (!funcAddy) {
                    return 2;
                }
                firstThunk->u1.Function = funcAddy;
                ++origFirstThunk;
                ++firstThunk;
            }
            ++importDesc;
        }
    }
    //std::cout << "thunks initialized award" << std::endl;
    //__debugbreak();

    // doing all TLS callbacks
    if (config.EnableTLS) {
        if (optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
            PIMAGE_TLS_DIRECTORY tlsEntry = reinterpret_cast<PIMAGE_TLS_DIRECTORY>((ULONGLONG)dllBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
            PIMAGE_TLS_CALLBACK* tlsCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsEntry->AddressOfCallBacks);
            while (tlsCallback && *tlsCallback) {
                (*tlsCallback)(reinterpret_cast<PVOID>(dllBase), DLL_PROCESS_ATTACH, NULL);
                ++tlsCallback;
            }
        }
    }
    //std::cout << "callbacks done award" << std::endl;
    //__debugbreak();

    // fixing SEH
    if (config.EnableSEH) {
        IMAGE_DATA_DIRECTORY sehDirectory = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (sehDirectory.Size) {
            _RtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>((ULONGLONG)dllBase + sehDirectory.VirtualAddress), sehDirectory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)dllBase);
        }
    }
    //__debugbreak();

    // calling DllMain
    pDllMain dllMain = reinterpret_cast<pDllMain>((ULONGLONG)dllBase + optHeader.AddressOfEntryPoint);
    if (!dllMain(dllBase, DLL_PROCESS_ATTACH, NULL)) {
        return 3;
    }
    //std::cout << "done!" << std::endl;
    return 0;
}