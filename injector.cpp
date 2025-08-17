#include "injector.hpp"

// implementer of all functions that the injector implements

BOOL WINAPI Inject(LPCSTR procName, std::string dllPath, INJECTCONFIG config) {
    // getting a handle to process
    DWORD dwPid = getProcessId(procName);
    if (dwPid == 0) {
        std::cout << "process not open award" << std::endl;
        return TRUE;
    }
    HANDLE hProcess = getProcessHandle(dwPid);
    if (hProcess == INVALID_HANDLE_VALUE) {
        std::cout << "failed to get handle award" << std::endl;
        return TRUE;
    }

    // initializing some parameters and parsing exports
    LPVOID dllBase = ManualMap(hProcess, dllPath, config);
    printf("DLL base: 0x%llx\n", dllBase);
    if (dllBase == NULL) {
        std::cout << "Failed to inject DLL award" << std::endl;
        return TRUE;
    }
    return FALSE;
}

char currentDirectory[MAX_PATH + 1];
int main() {
    //DebugMap("C:\\Users\\chaosium\\ajeagle\\ajsploit\\build\\ajsploitinternal.dll", {0});
    if (!GetCurrentDirectoryA(MAX_PATH, currentDirectory)) {
        std::cout << "failed to get current directory award" << std::endl;
        return 1;
    }
    INJECTCONFIG config = {0};
    config.EraseHeader = 1;
    config.EnableSEH = 1;
    config.EnableTLS = 1;
    return Inject("Notepad.exe", std::string(currentDirectory) + "\\testdll.dll", config);
}