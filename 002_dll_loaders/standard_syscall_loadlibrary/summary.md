# How Windows DLL Loading Works in Go: High-Level Overview

This code demonstrates the fundamental technique for loading and using Windows DLLs from Go. Here's how it works:

The build constraints (`//go:build windows`) at the top ensure this code only compiles when targeting Windows, which is essential since these Windows-specific functions don't exist on other platforms.

At its core, DLL loading in Windows follows three main steps, which our code implements:

1. **Loading the DLL** - `syscall.LoadLibrary()` brings the external code into our process's memory space. This makes the DLL's functions available to our program, but we don't yet know where they are.

2. **Finding function addresses** - `syscall.GetProcAddress()` locates specific functions inside the loaded DLL by name. This gives us a memory address (pointer) that we can call.

3. **Calling functions** - `syscall.Syscall()` executes the function at the address we found. It handles marshaling Go values into the format the C/C++ function expects, and converts return values back to Go.

The `defer syscall.FreeLibrary(handle)` statement ensures proper cleanup - it guarantees the DLL will be unloaded when our function finishes, preventing memory leaks even if errors occur.

Parameter passing works through `uintptr` values, which are essentially raw pointers or integer values that the DLL can interpret properly. The number passed to `Syscall` (like `2` in our example) indicates how many parameters we're sending.

The command-line argument handling makes this program flexible, letting users specify which DLL to load without recompiling the code.

This technique forms the foundation for any Go program that needs to interact with native Windows libraries.