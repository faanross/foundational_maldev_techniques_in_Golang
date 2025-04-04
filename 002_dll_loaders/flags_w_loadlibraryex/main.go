//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	// Check if DLL path was provided as command-line argument
	if len(os.Args) < 2 {
		fmt.Println("Usage: dllloader.exe <path_to_dll>")
		fmt.Println("Example: dllloader.exe C:\\temp\\testdll.dll")
		os.Exit(1)
	}

	// Get the DLL path from command-line arguments
	dllPath := os.Args[1]

	fmt.Printf("Loading DLL with flags: %s\n", dllPath)
	loadWithFlags(dllPath)
}

func loadWithFlags(dllPath string) {
	// Define LoadLibraryEx flags
	const (
		DONT_RESOLVE_DLL_REFERENCES        = 0x00000001
		LOAD_LIBRARY_AS_DATAFILE           = 0x00000002
		LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040
		LOAD_LIBRARY_AS_IMAGE_RESOURCE     = 0x00000020
		LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR   = 0x00000100
		LOAD_LIBRARY_SEARCH_SYSTEM32       = 0x00000800
	)

	// Load kernel32.dll to get LoadLibraryEx function
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibraryEx := kernel32.NewProc("LoadLibraryExW")
	getLastError := kernel32.NewProc("GetLastError")

	// Convert path to UTF16
	pathPtr, err := syscall.UTF16PtrFromString(dllPath)
	if err != nil {
		fmt.Printf("Error converting path: %v\n", err)
		return
	}

	// Call LoadLibraryEx with execution flag (not as datafile)
	// Using 0 for flags allows normal execution, unlike LOAD_LIBRARY_AS_DATAFILE
	handle, _, err := loadLibraryEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		0, // Using 0 for standard loading with execution privileges
	)

	if handle == 0 {
		errCode, _, _ := getLastError.Call()
		fmt.Printf("LoadLibraryEx failed: %v (Error code: %d/0x%X)\n", err, errCode, errCode)
		return
	}

	fmt.Printf("DLL loaded successfully. Handle: %v\n", handle)

	// Get function addresses for the exported functions we want to call
	getTestFunction := kernel32.NewProc("GetProcAddress")

	// Get TestFunction address
	testFuncName, _ := syscall.BytePtrFromString("TestFunction")
	testFuncAddr, _, err := getTestFunction.Call(
		handle,
		uintptr(unsafe.Pointer(testFuncName)),
	)

	if testFuncAddr == 0 {
		errCode, _, _ := getLastError.Call()
		fmt.Printf("GetProcAddress failed for TestFunction: %v (Error code: %d/0x%X)\n", err, errCode, errCode)
	} else {
		fmt.Printf("Found TestFunction at address: 0x%X\n", testFuncAddr)

		// Call the TestFunction
		r1, r2, lastErr := syscall.Syscall(testFuncAddr, 0, 0, 0, 0)
		if lastErr != 0 {
			fmt.Printf("Error calling TestFunction: %v\n", lastErr)
		} else {
			fmt.Printf("TestFunction called successfully. Returns: %d, %d\n", r1, r2)
		}
	}

	// Get AddNumbers address
	addNumFuncName, _ := syscall.BytePtrFromString("AddNumbers")
	addNumFuncAddr, _, err := getTestFunction.Call(
		handle,
		uintptr(unsafe.Pointer(addNumFuncName)),
	)

	if addNumFuncAddr == 0 {
		errCode, _, _ := getLastError.Call()
		fmt.Printf("GetProcAddress failed for AddNumbers: %v (Error code: %d/0x%X)\n", err, errCode, errCode)
	} else {
		fmt.Printf("Found AddNumbers at address: 0x%X\n", addNumFuncAddr)

		// Call AddNumbers with parameters
		a, b := 42, 58
		r1, _, lastErr := syscall.Syscall(addNumFuncAddr, 2, uintptr(a), uintptr(b), 0)
		if lastErr != 0 {
			fmt.Printf("Error calling AddNumbers: %v\n", lastErr)
		} else {
			fmt.Printf("AddNumbers(%d, %d) = %d\n", a, b, r1)
		}
	}

	// Try loading with a different flag for comparison
	fmt.Println("\nNow trying to load as datafile (can't execute functions):")
	datafileHandle, _, err := loadLibraryEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		LOAD_LIBRARY_AS_DATAFILE,
	)

	if datafileHandle == 0 {
		errCode, _, _ := getLastError.Call()
		fmt.Printf("LoadLibraryEx (datafile) failed: %v (Error code: %d/0x%X)\n", err, errCode, errCode)
	} else {
		fmt.Printf("DLL loaded as datafile. Handle: %v\n", datafileHandle)

		// Try to get function address (will likely fail with datafile loading)
		testFuncAddr, _, _ := getTestFunction.Call(
			datafileHandle,
			uintptr(unsafe.Pointer(testFuncName)),
		)

		if testFuncAddr == 0 {
			fmt.Printf("As expected, can't get function address when loaded as datafile\n")
		} else {
			fmt.Printf("Surprisingly found function at address: 0x%X\n", testFuncAddr)
		}

		// Clean up the datafile handle
		freeLibrary := kernel32.NewProc("FreeLibrary")
		freeLibrary.Call(datafileHandle)
	}

	// Demonstration of DONT_RESOLVE_DLL_REFERENCES flag
	fmt.Println("\nNow trying with DONT_RESOLVE_DLL_REFERENCES flag:")
	noResolveHandle, _, err := loadLibraryEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		DONT_RESOLVE_DLL_REFERENCES,
	)

	if noResolveHandle == 0 {
		errCode, _, _ := getLastError.Call()
		fmt.Printf("LoadLibraryEx (no resolve) failed: %v (Error code: %d/0x%X)\n", err, errCode, errCode)
	} else {
		fmt.Printf("DLL loaded with DONT_RESOLVE_DLL_REFERENCES. Handle: %v\n", noResolveHandle)
		fmt.Printf("DllMain initialization code was NOT executed\n")

		// Clean up this handle
		freeLibrary := kernel32.NewProc("FreeLibrary")
		freeLibrary.Call(noResolveHandle)
	}

	// Don't forget to free the main library
	freeLibrary := kernel32.NewProc("FreeLibrary")
	freeLibrary.Call(handle)

	fmt.Println("\nDLL has been unloaded")
}
