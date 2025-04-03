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
	mustLoading(dllPath)
}

func mustLoading(dllPath string) {
	// This will panic if the DLL cannot be loaded
	dll := syscall.MustLoadDLL(dllPath)
	defer dll.Release()

	// This will panic if the proc cannot be found
	testProc := dll.MustFindProc("TestFunction")

	// Call the function
	r1, r2, lastErr := testProc.Call()
	if lastErr != syscall.Errno(0) && lastErr.(syscall.Errno) != 0 {
		fmt.Printf("Error calling function: %v\n", lastErr)
		return
	}

	fmt.Printf("Function called successfully. Returns: %d, %d\n", r1, r2)

	addProc := dll.MustFindProc("AddNumbers")
	a, b := 15, 25
	r1, r2, lastErr = addProc.Call(uintptr(a), uintptr(b))
	if lastErr != syscall.Errno(0) && lastErr.(syscall.Errno) != 0 {
		fmt.Printf("Error calling AddNumbers: %v\n", lastErr)
		return
	}

	fmt.Printf("AddNumbers(%d, %d) = %d\n", a, b, r1)
}
