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
	standardLoading(dllPath)
}

func standardLoading(dllPath string) {
	// Your existing function code stays the same
	// Load the DLL into memory
	handle, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		fmt.Printf("Error loading library: %v\n", err)
		return
	}
	// Important: Always free the library when done
	defer syscall.FreeLibrary(handle)

	// Get a function address
	proc, err := syscall.GetProcAddress(handle, "TestFunction")
	if err != nil {
		fmt.Printf("Error getting proc address: %v\n", err)
		return
	}

	// Call the function (no parameters)
	r1, r2, lastErr := syscall.Syscall(proc, 0, 0, 0, 0)
	if lastErr != 0 {
		fmt.Printf("Error calling function: %v\n", lastErr)
		return
	}

	fmt.Printf("Function called successfully. Returns: %d, %d\n", r1, r2)

	// Get another function address (with parameters)
	addProc, err := syscall.GetProcAddress(handle, "AddNumbers")
	if err != nil {
		fmt.Printf("Error getting AddNumbers proc: %v\n", err)
		return
	}

	// Call function with two integer parameters
	a, b := 5, 7
	r1, r2, lastErr = syscall.Syscall(addProc, 2, uintptr(a), uintptr(b), 0)
	if lastErr != 0 {
		fmt.Printf("Error calling AddNumbers: %v\n", lastErr)
		return
	}

	fmt.Printf("AddNumbers(%d, %d) = %d\n", a, b, r1)
}
