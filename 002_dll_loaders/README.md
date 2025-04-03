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

==binary is approx 2.2MB==
![syscall results](./standard_syscall_loadlibrary/results.png)

## lazyloading

1. **Creating a Reference** - `syscall.NewLazyDLL()` doesn't actually load the DLL immediately, but instead creates a reference that will be resolved later. This is a key difference - no LoadLibrary call happens at this point.

2. **Defining Function References** - `dll.NewProc()` similarly doesn't look up function addresses right away, but creates placeholder references to functions that will be resolved when needed.

3. **Deferred Actual Loading** - The first call to `proc.Call()` triggers the actual loading process behind the scenes. Only at this point does the system perform the LoadLibrary operation and function address resolution.

- The most significant difference is timing - lazy loading defers all the actual DLL loading operations until the first function call, making the loading process invisible until functionality is actually used.
- This creates a smaller initial footprint and delays telltale API calls that might trigger security monitoring systems.

==binary is approx 2.2MB==
![syscall results](./lazyloading/results.png)