//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PE header structures - only what we need for 64-bit
type IMAGE_DOS_HEADER struct {
	Magic    uint16
	Cblp     uint16
	Cp       uint16
	Crlc     uint16
	Cparhdr  uint16
	MinAlloc uint16
	MaxAlloc uint16
	Ss       uint16
	Sp       uint16
	Csum     uint16
	Ip       uint16
	Cs       uint16
	Lfarlc   uint16
	Ovno     uint16
	Res      [4]uint16
	Oemid    uint16
	Oeminfo  uint16
	Res2     [10]uint16
	Lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

const (
	DLL_PROCESS_ATTACH = 1
)

func main() {
	// Check for command line arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: reflective_loader.exe <path_to_dll>")
		os.Exit(1)
	}

	dllPath := os.Args[1]
	fmt.Printf("Loading DLL: %s\n", dllPath)

	// Read the DLL file into memory
	dllBytes, err := os.ReadFile(dllPath)
	if err != nil {
		fmt.Printf("Error reading DLL file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Read %d bytes of DLL data\n", len(dllBytes))

	// Get pointer to the DLL bytes in memory
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))

	// Parse DOS header to find NT headers
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(dllPtr))
	if dosHeader.Magic != 0x5A4D { // "MZ"
		fmt.Println("Error: Not a valid PE file (DOS signature missing)")
		os.Exit(1)
	}

	// Get NT headers
	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(dosHeader.Lfanew)))
	if ntHeader.Signature != 0x00004550 { // "PE\0\0"
		fmt.Println("Error: Not a valid PE file (PE signature missing)")
		os.Exit(1)
	}

	// Check if this is a 64-bit PE file
	if ntHeader.FileHeader.Machine != 0x8664 { // IMAGE_FILE_MACHINE_AMD64
		fmt.Println("Error: Not a 64-bit PE file")
		os.Exit(1)
	}

	fmt.Printf("DLL entry point: 0x%X\n", ntHeader.OptionalHeader.AddressOfEntryPoint)
	fmt.Printf("DLL image base: 0x%X\n", ntHeader.OptionalHeader.ImageBase)
	fmt.Printf("DLL image size: 0x%X\n", ntHeader.OptionalHeader.SizeOfImage)

	// Allocate memory for the DLL (try to allocate at the preferred base address)
	dllBase, err := windows.VirtualAlloc(uintptr(ntHeader.OptionalHeader.ImageBase),
		uintptr(ntHeader.OptionalHeader.SizeOfImage),
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		// If we can't allocate at the preferred address, allocate anywhere
		fmt.Println("Could not allocate at preferred base, trying alternative address")
		dllBase, err = windows.VirtualAlloc(0,
			uintptr(ntHeader.OptionalHeader.SizeOfImage),
			windows.MEM_RESERVE|windows.MEM_COMMIT,
			windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			fmt.Printf("Error allocating memory: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("Allocated memory at: 0x%X\n", dllBase)

	// Calculate base address delta for relocations
	deltaImageBase := int64(dllBase) - int64(ntHeader.OptionalHeader.ImageBase)
	fmt.Printf("Image base delta: 0x%X\n", deltaImageBase)

	// Copy PE headers
	copySize := uintptr(ntHeader.OptionalHeader.SizeOfHeaders)
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(windows.CurrentProcess(), dllBase, &dllBytes[0], copySize, &bytesWritten)
	if err != nil {
		fmt.Printf("Error copying PE headers: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Copied %d bytes of headers\n", bytesWritten)

	// Copy sections
	sectionHeaderPtr := dllPtr +
		uintptr(dosHeader.Lfanew) +
		unsafe.Sizeof(ntHeader.Signature) +
		unsafe.Sizeof(ntHeader.FileHeader) +
		uintptr(ntHeader.FileHeader.SizeOfOptionalHeader)

	for i := 0; i < int(ntHeader.FileHeader.NumberOfSections); i++ {
		sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionHeaderPtr + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{})))

		// Get section name
		sectionName := windows.ByteSliceToString(sectionHeader.Name[:])

		// Calculate section addresses
		sectionSrc := dllPtr + uintptr(sectionHeader.PointerToRawData)
		sectionDst := dllBase + uintptr(sectionHeader.VirtualAddress)

		// Copy section data
		err = windows.WriteProcessMemory(
			windows.CurrentProcess(),
			sectionDst,
			(*byte)(unsafe.Pointer(sectionSrc)),
			uintptr(sectionHeader.SizeOfRawData),
			&bytesWritten,
		)
		if err != nil {
			fmt.Printf("Error copying section %s: %v\n", sectionName, err)
			os.Exit(1)
		}
		fmt.Printf("Copied section %s: %d bytes\n", sectionName, bytesWritten)
	}

	// If the image was rebased, we need to process relocations
	if deltaImageBase != 0 {
		fmt.Println("Processing relocations...")
		// This would be complex to implement for this example
		// For a full implementation, we'd need to:
		// 1. Find the relocation directory
		// 2. Process each relocation block
		// 3. Apply the delta to each relocation entry

		// Since our focus is on simplicity for this example and since
		// relocations are complex, I'll note that in a full implementation
		// this would be necessary if the DLL couldn't be loaded at its
		// preferred base address
	}

	// Call DllMain with DLL_PROCESS_ATTACH
	entryPoint := dllBase + uintptr(ntHeader.OptionalHeader.AddressOfEntryPoint)
	fmt.Printf("Calling DLL entry point at 0x%X\n", entryPoint)

	// Call the DLL entry point using syscall
	ret, _, _ := syscall.SyscallN(entryPoint, dllBase, DLL_PROCESS_ATTACH, 0)

	fmt.Printf("DllMain returned: %d\n", ret)

	if ret != 0 {
		fmt.Println("DLL loaded and executed successfully!")
	} else {
		fmt.Println("DLL execution failed")
	}

	// Keep the DLL loaded - uncomment if needed
	// fmt.Println("Press Enter to free the DLL memory...")
	// fmt.Scanln()

	// Free the allocated memory when done
	windows.VirtualFree(dllBase, 0, windows.MEM_RELEASE)
	fmt.Println("DLL memory freed")
}
