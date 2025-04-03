// testdll.cpp
#include <windows.h>
#include <stdio.h>

extern "C" {
    __declspec(dllexport) void TestFunction() {
        MessageBoxA(NULL, "TestFunction called!", "TestDLL", MB_OK);
    }

    __declspec(dllexport) int AddNumbers(int a, int b) {
        return a + b;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // NOTE: This path C:\temp\... is relative to the TARGET Windows machine
            // Ensure C:\temp exists and has write permissions *on the Windows machine* where the DLL will run.
            FILE* f = fopen("C:\\temp\\testdll_loaded.txt", "w");
            if (f) {
                fprintf(f, "TestDLL loaded at address: %p\n", hinstDLL);
                fclose(f);
            }
            break;
    }
    return TRUE;
}