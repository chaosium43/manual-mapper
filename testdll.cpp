#include <windows.h>
#include <iostream>

// little file for the purposes of building a DLL that can test the manual map injector
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch(fdwReason) { 
        case DLL_PROCESS_ATTACH:
            FreeConsole();
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
            freopen("CONIN$", "r", stdin);
            SetConsoleTitleA("Test DLL");
            printf("Test DLL has been successfully injected\n");
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}