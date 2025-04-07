//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
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
	fmt.Println("Starting shellcode execution test...")

	// Create a lazy DLL reference
	fmt.Println("Creating lazy DLL reference...")
	dll := syscall.NewLazyDLL(dllPath)

	// Just loading the DLL should trigger the shellcode in DllMain
	fmt.Println("DLL reference created - at this point DllMain should have executed")
	fmt.Println("If calc.exe does not appear, we'll try explicit invocation...")

	// Small pause to see if the automatic execution worked
	time.Sleep(1 * time.Second)

	// As a backup, call the exported LaunchCalc function which also executes the shellcode
	fmt.Println("Getting LaunchCalc function pointer...")
	launchCalcProc := dll.NewProc("LaunchCalc")

	fmt.Println("Explicitly calling LaunchCalc to execute shellcode...")
	r1, _, lastErr := launchCalcProc.Call()

	// Check result
	fmt.Printf("LaunchCalc returned: %d (non-zero means success)\n", r1)
	fmt.Printf("Error status: %v\n", lastErr)

	// Finally check if we can still access the DLL
	fmt.Println("Checking if DLL is still accessible by getting AddNumbers function...")
	dll.NewProc("AddNumbers")

	fmt.Println("Shellcode execution test complete")

	// If calculator didn't appear, the shellcode execution failed
	if r1 == 0 {
		fmt.Println("WARNING: Shellcode execution appears to have failed!")
	}
}
