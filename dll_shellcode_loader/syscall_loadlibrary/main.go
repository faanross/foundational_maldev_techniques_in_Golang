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
	standardLoading(dllPath)
}

func standardLoading(dllPath string) {

	// Get a handle to the DLL
	handle, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		fmt.Printf("Error loading library: %v\n", err)
		return
	}

	defer syscall.FreeLibrary(handle)

	// Get a function address using handle to DLL + name of function
	proc, err := syscall.GetProcAddress(handle, "LaunchCalc")
	if err != nil {
		fmt.Printf("Error getting proc address: %v\n", err)
		return
	}

	// Call the function
	r1, _, lastErr := syscall.Syscall(proc, 0, 0, 0, 0)

	// Check result, NOTE here !0 is success, inverse of "normal Go"
	fmt.Printf("LaunchCalc returned: %d (non-zero means success)\n", r1)
	if r1 != 0 {
		fmt.Println("Shellcode executed successfully!")
	} else {
		fmt.Printf("ERROR: Shellcode execution failed: %v\n", lastErr)
	}

}
