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
	launchCalc := dll.MustFindProc("LaunchCalc")

	// Call the function
	r1, _, lastErr := launchCalc.Call()

	// Check result, NOTE here !0 is success, inverse of "normal Go"
	fmt.Printf("LaunchCalc returned: %d (non-zero means success)\n", r1)
	if r1 != 0 {
		fmt.Println("Shellcode executed successfully!")
	} else {
		fmt.Printf("ERROR: Shellcode execution failed: %v\n", lastErr)
	}

}
