## overview
This entire section deals with the fundamental scenario where you have shellcode embedded inside a DLL, which you then want to execute.
For these proof-of-concepts we will go the traditional 'launch calc.exe on Win x64' route.
Also I will be ignoring caving, cool idea and all but not something that it realistically practical anymore, and I don't really see it as being foundational knowledge to other more advanced techniques, really just its own little quirky island.

See: `./dll_shellcode_calc` for source file to generate shellcode DLL.

```go
x86_64-w64-mingw32-g++ dll_calc.cpp -o dll_calc.dll -shared -static-libgcc -static-libstdc++ -luser32
```

