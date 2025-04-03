//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"syscall"
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

	fmt.Printf("Loading DLL: %s\n", dllPath)

	// Call the standardLoading function with the provided path
	lazyLoading(dllPath)
}

func lazyLoading(dllPath string) {
	// Create a lazy DLL reference
	dll := syscall.NewLazyDLL(dllPath)

	// This doesn't actually load the DLL yet
	// The DLL is loaded on the first call to a proc

	// Get a reference to a procedure
	testProc := dll.NewProc("TestFunction")

	// This call will load the DLL if it's not already loaded
	r1, r2, lastErr := testProc.Call()
	if lastErr != syscall.Errno(0) && lastErr.(syscall.Errno) != 0 {
		fmt.Printf("Error calling function: %v\n", lastErr)
		return
	}

	fmt.Printf("Function called successfully. Returns: %d, %d\n", r1, r2)

	// Try another function
	addProc := dll.NewProc("AddNumbers")
	a, b := 10, 20
	r1, r2, lastErr = addProc.Call(uintptr(a), uintptr(b))

	// Many Windows API functions return non-zero error codes even on success
	// So we need to check if it's a "real" error
	if lastErr != syscall.Errno(0) && lastErr.(syscall.Errno) != 0 {
		fmt.Printf("Error calling AddNumbers: %v\n", lastErr)
		return
	}

	fmt.Printf("AddNumbers(%d, %d) = %d\n", a, b, r1)
}
