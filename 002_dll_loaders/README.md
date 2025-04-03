## test_dll_generator
Simple dll (`testdll.cpp`) to test loading techniques, does 3 things:
- Show a GUI pop-up message when `TestFunction` is called.
- Return the sum of two numbers when `AddNumbers` is called.
- Write to a log file (`C:\Windows\Temp\testdll_loaded.txt`) containing ref to DLL memory address when the DLL is loaded.

To compile on mac for win
```shell
x86_64-w64-mingw32-g++ testdll.cpp -o testdll.dll -shared -static-libgcc -static-libstdc++ -luser32
```


## standard_syscall_loadlibrary

This is the most direct method using `syscall` library, maps closely to the Windows API.

1. **Loading the DLL** - `syscall.LoadLibrary()` loads DLL code into our process's memory space. 

2. **Finding function addresses** - `syscall.GetProcAddress()` locates specific functions inside the loaded DLL by name, giving us a memory address (pointer) that we can then call.

3. **Calling functions** - `syscall.Syscall()` executes the function at the address located in #2. It also marshals Go values into the format the C/C++ function expects, and converts return values back to Go.

![./002_dll_loaders/standard_syscall_loadlibrary/results.png]


