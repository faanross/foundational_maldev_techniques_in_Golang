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

// Configuration - Change this to target different exported functions
var targetFunctionName = "LaunchCalc"

var kernel32DLL = windows.NewLazyDLL("kernel32.dll")
var getProcAddressProc = kernel32DLL.NewProc("GetProcAddress")

// --- PE Structures ---

type IMAGE_DOS_HEADER struct {
	Magic    uint16     // Magic number (MZ)
	Cblp     uint16     // Bytes on last page of file
	Cp       uint16     // Pages in file
	Crlc     uint16     // Relocations
	Cparhdr  uint16     // Size of header in paragraphs
	MinAlloc uint16     // Minimum extra paragraphs needed
	MaxAlloc uint16     // Maximum extra paragraphs needed
	Ss       uint16     // Initial (relative) SS value
	Sp       uint16     // Initial SP value
	Csum     uint16     // Checksum
	Ip       uint16     // Initial IP value
	Cs       uint16     // Initial (relative) CS value
	Lfarlc   uint16     // File address of relocation table
	Ovno     uint16     // Overlay number
	Res      [4]uint16  // Reserved words
	Oemid    uint16     // OEM identifier (for e_oeminfo)
	Oeminfo  uint16     // OEM information; e_oemid specific
	Res2     [10]uint16 // Reserved words
	Lfanew   int32      // File address of new exe header (PE header offset)
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16 // Architecture type
	NumberOfSections     uint16 // Number of sections
	TimeDateStamp        uint32 // Time and date stamp
	PointerToSymbolTable uint32 // Pointer to symbol table
	NumberOfSymbols      uint32 // Number of symbols
	SizeOfOptionalHeader uint16 // Size of optional header
	Characteristics      uint16 // File characteristics
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32 // RVA of the directory
	Size           uint32 // Size of the directory
}

// Note: This is the 64-bit version
type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16 // Magic number (0x20b for PE32+)
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32 // RVA of the entry point
	BaseOfCode                  uint32
	ImageBase                   uint64 // Preferred base address
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32 // Total size of the image in memory
	SizeOfHeaders               uint32 // Size of headers (DOS + PE + Section Headers)
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY // Array of data directories
}

// Note: This is the 64-bit version
type IMAGE_NT_HEADERS64 struct {
	Signature      uint32 // PE signature ("PE\0\0")
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte // Section name (null-padded)
	VirtualSize          uint32  // Actual size used in memory
	VirtualAddress       uint32  // RVA of the section
	SizeOfRawData        uint32  // Size of section data on disk
	PointerToRawData     uint32  // File offset of section data
	PointerToRelocations uint32  // File offset of relocations
	PointerToLinenumbers uint32  // File offset of line numbers
	NumberOfRelocations  uint16  // Number of relocations
	NumberOfLinenumbers  uint16  // Number of line numbers
	Characteristics      uint32  // Section characteristics (flags like executable, readable, writable)
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32 // RVA of the DLL name string
	Base                  uint32 // Starting ordinal number
	NumberOfFunctions     uint32 // Total number of exported functions
	NumberOfNames         uint32 // Number of functions exported by name
	AddressOfFunctions    uint32 // RVA of the Export Address Table (EAT)
	AddressOfNames        uint32 // RVA of the Export Name Pointer Table (ENPT)
	AddressOfNameOrdinals uint32 // RVA of the Export Ordinal Table (EOT)
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32 // RVA to the Import Lookup Table (ILT) (or Characteristics)
	TimeDateStamp      uint32 // Timestamp of the bound DLL
	ForwarderChain     uint32 // Index into FirstThunk array
	Name               uint32 // RVA to the DLL name string
	FirstThunk         uint32 // RVA to the Import Address Table (IAT)
}

// IMAGE_IMPORT_BY_NAME structure is implicitly used:
// struct {
//   WORD Hint; // Ordinal hint
//   CHAR Name[1]; // Function name (null-terminated string)
// }

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32 // RVA of the page this block applies to
	SizeOfBlock    uint32 // Total size of this relocation block (including header)
}

// Relocation entry is a WORD (uint16) where:
// Top 4 bits = Type (e.g., IMAGE_REL_BASED_DIR64 = 10)
// Bottom 12 bits = Offset within the page (VirtualAddress)

// --- Constants ---
const (
	IMAGE_DOS_SIGNATURE             = 0x5A4D           // "MZ"
	IMAGE_NT_SIGNATURE              = 0x00004550       // "PE\0\0"
	IMAGE_FILE_MACHINE_AMD64        = 0x8664           // Target architecture x64
	IMAGE_DIRECTORY_ENTRY_EXPORT    = 0                // Export Directory index
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 1                // Import Directory index
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5                // Base Relocation Table index
	IMAGE_DIRECTORY_ENTRY_IAT       = 12               // Import Address Table index (often same RVA as FirstThunk in Import Dir)
	IMAGE_REL_BASED_DIR64           = 10               // Relocation type for 64-bit addresses
	IMAGE_ORDINAL_FLAG64            = uintptr(1) << 63 // Flag indicating import by ordinal for 64-bit
	DLL_PROCESS_ATTACH              = 1                // Reason for calling DllMain
)

// --- Main Function ---
func main() {
	// 1. Setup & Read DLL
	if len(os.Args) < 2 {
		fmt.Println("Usage: reflective_loader.exe <path_to_dll>")
		os.Exit(1)
	}

	dllPath := os.Args[1]
	fmt.Printf("[+] Loading DLL: %s\n", dllPath)
	fmt.Printf("[+] Target function: %s\n", targetFunctionName)

	dllBytes, err := os.ReadFile(dllPath)
	if err != nil {
		fmt.Printf("[-] Error reading DLL file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Read %d bytes of DLL data\n", len(dllBytes))

	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0])) // Base address of DLL bytes in *this* process

	// 2. Parse PE Headers
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(dllPtr))
	if dosHeader.Magic != IMAGE_DOS_SIGNATURE {
		fmt.Println("[-] Error: Not a valid PE file (Invalid DOS signature)")
		os.Exit(1)
	}
	fmt.Printf("[+] DOS Header: Magic: 0x%X, PE Header Offset: 0x%X\n", dosHeader.Magic, dosHeader.Lfanew)

	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(dosHeader.Lfanew)))
	if ntHeader.Signature != IMAGE_NT_SIGNATURE {
		fmt.Println("[-] Error: Not a valid PE file (Invalid PE signature)")
		os.Exit(1)
	}
	if ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
		fmt.Println("[-] Error: Not a 64-bit PE file (Machine type != AMD64)")
		os.Exit(1)
	}
	fmt.Printf("[+] PE file confirmed 64-bit (Machine type: 0x%X)\n", ntHeader.FileHeader.Machine)
	fmt.Printf("[+] DLL Entry Point RVA: 0x%X\n", ntHeader.OptionalHeader.AddressOfEntryPoint)
	fmt.Printf("[+] DLL Preferred Image Base: 0x%X\n", ntHeader.OptionalHeader.ImageBase)
	fmt.Printf("[+] DLL Image Size: 0x%X\n", ntHeader.OptionalHeader.SizeOfImage)
	fmt.Printf("[+] DLL Size of Headers: 0x%X\n", ntHeader.OptionalHeader.SizeOfHeaders)

	// 3. Allocate Memory for DLL
	fmt.Printf("[+] Attempting to allocate 0x%X bytes at preferred base address: 0x%X\n",
		ntHeader.OptionalHeader.SizeOfImage, ntHeader.OptionalHeader.ImageBase)

	// Try allocating at the preferred base address
	allocBase, err := windows.VirtualAlloc(
		uintptr(ntHeader.OptionalHeader.ImageBase), // Specify preferred base
		uintptr(ntHeader.OptionalHeader.SizeOfImage),
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_EXECUTE_READWRITE, // Start with RWX, can refine later
	)

	if err != nil {
		fmt.Println("[*] Could not allocate at preferred base, allocating at arbitrary address...")
		allocBase, err = windows.VirtualAlloc(
			0, // Let the system choose the address
			uintptr(ntHeader.OptionalHeader.SizeOfImage),
			windows.MEM_RESERVE|windows.MEM_COMMIT,
			windows.PAGE_EXECUTE_READWRITE,
		)
		if err != nil {
			fmt.Printf("[-] Error allocating memory for DLL: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("[+] Allocated memory for DLL at: 0x%X\n", allocBase)
	// Defer release of the allocated memory
	defer func() {
		err := windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
		if err != nil {
			fmt.Printf("[!] Warning: Failed to free allocated DLL memory at 0x%X: %v\n", allocBase, err)
		} else {
			fmt.Println("[+] DLL memory freed successfully.")
		}
	}()

	// 4. Copy Headers and Sections
	fmt.Println("[+] Copying PE headers...")
	copySizeHeaders := uintptr(ntHeader.OptionalHeader.SizeOfHeaders)
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(windows.CurrentProcess(), allocBase, &dllBytes[0], copySizeHeaders, &bytesWritten)
	if err != nil || bytesWritten != copySizeHeaders {
		fmt.Printf("[-] Error copying PE headers: %v (written: %d)\n", err, bytesWritten)
		windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE) // Clean up allocated memory
		os.Exit(1)
	}
	fmt.Printf("[+] Copied %d bytes of headers\n", bytesWritten)

	fmt.Println("[+] Copying sections...")
	// Calculate pointer to the first section header
	sectionHeaderPtr := uintptr(unsafe.Pointer(ntHeader)) + unsafe.Sizeof(*ntHeader) // Start after NT Header
	numSections := int(ntHeader.FileHeader.NumberOfSections)
	sectionHeaderSize := unsafe.Sizeof(IMAGE_SECTION_HEADER{})

	for i := 0; i < numSections; i++ {
		sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionHeaderPtr + uintptr(i)*sectionHeaderSize))
		sectionName := windows.ByteSliceToString(sectionHeader.Name[:]) // More robust way to get name

		// Calculate source and destination addresses
		sectionSrc := dllPtr + uintptr(sectionHeader.PointerToRawData)
		sectionDst := allocBase + uintptr(sectionHeader.VirtualAddress)

		sizeToCopy := uintptr(sectionHeader.SizeOfRawData)
		if sizeToCopy == 0 {
			if sectionHeader.VirtualSize > 0 {
				fmt.Printf("    [*] Section %s has no raw data but has virtual size (likely .bss), skipping copy (memory is already zeroed).\n", sectionName)
			} else {
				fmt.Printf("    [*] Skipping section %s (SizeOfRawData is zero)\n", sectionName)
			}
			continue // Nothing to copy from file
		}

		fmt.Printf("    [*] Copying section %s (RawSize: 0x%X) from file offset 0x%X to VA 0x%X\n",
			sectionName, sizeToCopy, sectionHeader.PointerToRawData, sectionDst)

		err = windows.WriteProcessMemory(
			windows.CurrentProcess(),
			sectionDst,
			(*byte)(unsafe.Pointer(sectionSrc)), // Pointer to start of section data in file buffer
			sizeToCopy,
			&bytesWritten,
		)
		if err != nil || bytesWritten != sizeToCopy {
			fmt.Printf("    [-] Error copying section %s: %v (written: %d)\n", sectionName, err, bytesWritten)
			windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
			os.Exit(1)
		}
		fmt.Printf("    [+] Copied section %s: %d bytes\n", sectionName, bytesWritten)
	}
	fmt.Println("[+] Finished copying sections.")

	// 5. Process Relocations (if needed)
	deltaImageBase := int64(allocBase) - int64(ntHeader.OptionalHeader.ImageBase) // Use signed int64 for delta
	fmt.Printf("[+] Calculated Image Base Delta: 0x%X\n", deltaImageBase)

	if deltaImageBase != 0 {
		fmt.Println("[+] Image rebased, processing relocations...")
		relocDirRVA := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
		relocDirSize := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size

		if relocDirRVA == 0 || relocDirSize == 0 {
			fmt.Println("[!] Warning: Image was rebased, but no relocation directory found or it's empty!")
			// This might be okay if the DLL was compiled without needing relocations (e.g., /FIXED), but often indicates a problem.
		} else {
			fmt.Printf("[+] Relocation Directory RVA: 0x%X, Size: 0x%X\n", relocDirRVA, relocDirSize)
			processRelocations(allocBase, relocDirRVA, relocDirSize, deltaImageBase)
		}
	} else {
		fmt.Println("[+] Image loaded at preferred base address, no relocations needed.")
	}

	// 6. Process Import Address Table (IAT) - *** CRITICAL STEP ***
	fmt.Println("[+] Processing Import Address Table (IAT)...")
	importDirRVA := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
	// importDirSize := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size // Size isn't needed for iteration

	if importDirRVA == 0 {
		fmt.Println("[*] No Import Directory found (DLL has no imports or is stripped).")
	} else {
		fmt.Printf("[+] Import Directory RVA: 0x%X\n", importDirRVA)
		importDescSize := unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{})
		importDescPtr := allocBase + uintptr(importDirRVA) // Absolute address of first descriptor

		for i := 0; ; i++ {
			importDesc := (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importDescPtr + uintptr(i)*importDescSize))

			// Check for the null terminator descriptor
			if importDesc.Name == 0 && importDesc.FirstThunk == 0 {
				fmt.Printf("[+] Processed %d import descriptors.\n", i)
				break
			}

			dllNameRVA := importDesc.Name
			dllNamePtr := (*byte)(unsafe.Pointer(allocBase + uintptr(dllNameRVA)))
			dllName := windows.BytePtrToString(dllNamePtr)
			fmt.Printf("    [->] Processing imports for: %s\n", dllName)

			// Load the required dependency DLL
			hModule, err := windows.LoadLibrary(dllName)
			if err != nil {
				// This is usually fatal
				fmt.Printf("    [-] FATAL: Failed to load dependency library %s: %v\n", dllName, err)
				windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
				os.Exit(1)
			}
			// Note: We don't typically FreeLibrary here as the loaded DLL needs them
			fmt.Printf("        [+] Loaded %s at handle 0x%X\n", dllName, hModule)

			// Determine the table addresses (ILT and IAT)
			// If OriginalFirstThunk is 0 (e.g., after binding), the ILT points directly to the IAT.
			// Otherwise, ILT has lookup info, IAT needs patching.
			iltRVA := importDesc.OriginalFirstThunk
			if iltRVA == 0 {
				iltRVA = importDesc.FirstThunk // Use IAT RVA if ILT RVA is zero
			}
			iatRVA := importDesc.FirstThunk

			iltBase := allocBase + uintptr(iltRVA) // Absolute address of Import Lookup Table
			iatBase := allocBase + uintptr(iatRVA) // Absolute address of Import Address Table (to be patched)

			entrySize := unsafe.Sizeof(uintptr(0)) // Size of a pointer (8 bytes on x64)
			j := uintptr(0)                        // Index for entries

			for {
				iltEntryAddr := iltBase + (j * entrySize)
				iatEntryAddr := iatBase + (j * entrySize)

				iltEntry := *(*uintptr)(unsafe.Pointer(iltEntryAddr))
				if iltEntry == 0 {
					fmt.Printf("        [+] Finished processing imports for %s.\n", dllName)
					break // Null terminator for this descriptor's import list
				}

				var funcAddr uintptr
				var procErr error
				var importName string = "by Ordinal"

				// Check if importing by ordinal or name
				if iltEntry&IMAGE_ORDINAL_FLAG64 != 0 {
					// Import by Ordinal
					ordinal := iltEntry & 0xFFFF // Low 16 bits are the ordinal
					importName = fmt.Sprintf("Ordinal %d", ordinal)
					// GetProcAddress expects ordinal in lower word, zero in higher word
					// Import by Ordinal - Use direct syscall to kernel32's GetProcAddress
					// SyscallN(funcAddr, nargs, arg1, arg2, arg3, ...)
					// GetProcAddress(hModule, lpProcName) -> lpProcName is the ordinal uintptr
					ret, _, callErr := syscall.SyscallN(getProcAddressProc.Addr(), uintptr(hModule), ordinal)

					// Check for errors from the syscall itself
					if callErr != 0 {
						// The syscall failed to execute (permissions, invalid address, etc.)
						procErr = callErr // Use the syscall error
						funcAddr = 0      // Ensure funcAddr is zero on error
					} else if ret == 0 {
						// GetProcAddress succeeded but returned NULL (function not found)
						// We don't call GetLastError here for simplicity, just treat NULL as error
						procErr = fmt.Errorf("GetProcAddress returned NULL for %s", importName)
						funcAddr = 0 // Ensure funcAddr is zero on error
					} else {
						// Success, ret holds the function pointer
						funcAddr = ret
						procErr = nil // Clear any previous error attempt
					}
				} else {
					// Import by Name
					// iltEntry is an RVA to IMAGE_IMPORT_BY_NAME structure
					hintNameRVA := uint32(iltEntry) // RVA to IMAGE_IMPORT_BY_NAME
					hintNameAddr := allocBase + uintptr(hintNameRVA)
					// IMAGE_IMPORT_BY_NAME structure: WORD Hint; CHAR Name[1];
					funcNamePtr := (*byte)(unsafe.Pointer(hintNameAddr + 2)) // Skip the 2-byte Hint
					funcName := windows.BytePtrToString(funcNamePtr)
					importName = fmt.Sprintf("Function '%s'", funcName)
					funcAddr, procErr = windows.GetProcAddress(hModule, funcName)
				}

				// Check if GetProcAddress failed
				if procErr != nil || funcAddr == 0 {
					fmt.Printf("        [-] FATAL: Failed to resolve import %s from %s: %v (Addr: 0x%X)\n", importName, dllName, procErr, funcAddr)
					windows.FreeLibrary(hModule) // Attempt cleanup
					windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
					os.Exit(1)
				}

				// Patch the IAT entry with the resolved address
				// We allocated with RWX, so direct write should work here.
				// If it didn't, we'd need WriteProcessMemory.
				*(*uintptr)(unsafe.Pointer(iatEntryAddr)) = funcAddr
				fmt.Printf("        [+] Resolved %s -> 0x%X. Patched IAT at 0x%X.\n", importName, funcAddr, iatEntryAddr)

				j++ // Move to next import entry
			}
		}
	}
	fmt.Println("[+] IAT Processing Complete.")

	// 7. Adjust Memory Permissions (Optional but Recommended)
	// At this point, ideally, you would iterate through the sections again
	// and use VirtualProtect to set more appropriate permissions.
	// E.g., .text -> PAGE_EXECUTE_READ, .rdata -> PAGE_READONLY, .data -> PAGE_READWRITE
	// This reduces the attack surface compared to leaving everything RWX.
	fmt.Println("[*] Note: Memory permissions remain RWX. Consider using VirtualProtect for hardening.")

	// 8. Find Exported Target Function
	fmt.Printf("[+] Locating target exported function: %s\n", targetFunctionName)
	exportDirRVA := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	exportDirSize := ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
	var targetFuncAddr uintptr
	var targetFuncFound bool = false

	if exportDirRVA == 0 || exportDirSize == 0 {
		fmt.Println("[-] Error: DLL has no export directory or it's empty.")
		// Cannot proceed if we need to call a specific function
		windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
		os.Exit(1)
	} else {
		fmt.Printf("[+] Export Directory RVA: 0x%X, Size: 0x%X\n", exportDirRVA, exportDirSize)
		exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(allocBase + uintptr(exportDirRVA)))
		fmt.Printf("    Number of Functions: %d\n", exportDir.NumberOfFunctions)
		fmt.Printf("    Number of Names: %d\n", exportDir.NumberOfNames)
		fmt.Printf("    AddressOfFunctions RVA: 0x%X\n", exportDir.AddressOfFunctions)
		fmt.Printf("    AddressOfNames RVA: 0x%X\n", exportDir.AddressOfNames)
		fmt.Printf("    AddressOfNameOrdinals RVA: 0x%X\n", exportDir.AddressOfNameOrdinals)

		// Get pointers to the export tables
		eatBase := allocBase + uintptr(exportDir.AddressOfFunctions)    // Export Address Table base
		enptBase := allocBase + uintptr(exportDir.AddressOfNames)       // Export Name Pointer Table base
		eotBase := allocBase + uintptr(exportDir.AddressOfNameOrdinals) // Export Ordinal Table base

		fmt.Println("[+] Searching Export Name Pointer Table...")
		for i := uint32(0); i < exportDir.NumberOfNames; i++ {
			// Get RVA of the function name string from ENPT
			nameRVA := *(*uint32)(unsafe.Pointer(enptBase + uintptr(i*4))) // Names table entries are 4 bytes (RVAs)
			// Get the actual function name string
			funcNamePtr := (*byte)(unsafe.Pointer(allocBase + uintptr(nameRVA)))
			funcName := windows.BytePtrToString(funcNamePtr)

			// Get the ordinal for this name from EOT
			// EOT entries are 2 bytes (WORDs), index matches ENPT index
			ordinal := *(*uint16)(unsafe.Pointer(eotBase + uintptr(i*2)))
			// The ordinal is an index into the EAT (relative to Export Directory Base ordinal)

			// Get the function's RVA from EAT using the ordinal
			// EAT entries are 4 bytes (RVAs)
			// Ordinal needs to be adjusted by the Base if it's not 0 or 1 (usually it is 0)
			// However, the ordinal value read from EOT *is* the direct index needed for EAT.
			funcRVA := *(*uint32)(unsafe.Pointer(eatBase + uintptr(ordinal*4)))

			fmt.Printf("    [%d] Name: '%s', Ordinal: %d, Function RVA: 0x%X\n", i, funcName, ordinal, funcRVA)

			if funcName == targetFunctionName {
				targetFuncAddr = allocBase + uintptr(funcRVA) // Calculate absolute address
				targetFuncFound = true
				fmt.Printf("[+] Found target function '%s' at address 0x%X (RVA: 0x%X)\n",
					targetFunctionName, targetFuncAddr, funcRVA)
				break // Stop searching once found
			}
		}
	}

	// 9. Call DllMain and Target Function
	dllEntryRVA := ntHeader.OptionalHeader.AddressOfEntryPoint
	if dllEntryRVA == 0 {
		fmt.Println("[!] Warning: DLL has no entry point (AddressOfEntryPoint is 0). Skipping DllMain call.")
	} else {
		entryPointAddr := allocBase + uintptr(dllEntryRVA)
		fmt.Printf("[+] Calling DLL entry point (DllMain) at 0x%X with DLL_PROCESS_ATTACH\n", entryPointAddr)

		// Call DllMain: BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
		// Arguments: hinstDLL = base address of DLL (allocBase)
		//            fdwReason = DLL_PROCESS_ATTACH (1)
		//            lpvReserved = NULL (0) or non-NULL for static TLS
		ret, _, callErr := syscall.SyscallN(entryPointAddr, allocBase, DLL_PROCESS_ATTACH, 0)
		if callErr != 0 {
			fmt.Printf("    [-] Error calling DllMain: %v\n", callErr)
			// Decide if this is fatal. If DllMain fails, the DLL might be in an unstable state.
		} else {
			// The return value of DllMain for ATTACH indicates success (non-zero) or failure (zero)
			fmt.Printf("    [+] DllMain returned: %d (%s)\n", ret, map[uintptr]string{0: "FALSE", 1: "TRUE"}[ret])
			if ret == 0 { // DLL_PROCESS_ATTACH returned FALSE
				fmt.Println("    [-] DllMain failed initialization (returned FALSE). Aborting function call.")
				windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
				os.Exit(1)
			}
		}
	}

	// Call the target exported function if found
	if !targetFuncFound {
		fmt.Printf("[-] Error: Target function '%s' not found in exports. Cannot call.\n", targetFunctionName)
		// Depending on the goal, you might exit here or just finish if DllMain was the only goal.
		windows.VirtualFree(allocBase, 0, windows.MEM_RELEASE)
		os.Exit(1)
	} else {
		fmt.Printf("[+] Calling target function '%s' at 0x%X\n", targetFunctionName, targetFuncAddr)

		// Assume the target function matches the signature: BOOL LaunchCalc()
		// It takes no arguments.
		ret, _, callErr := syscall.SyscallN(targetFuncAddr, 0, 0, 0) // Pass 0 for unused args

		if callErr != 0 {
			fmt.Printf("    [-] Error calling %s: %v\n", targetFunctionName, callErr)
		} else {
			// Check the return value based on your DLL function's definition
			fmt.Printf("    [+] %s returned: %d (In your DLL, non-zero usually means success)\n", targetFunctionName, ret)
			if ret != 0 {
				fmt.Println("[+] Target function executed successfully!")
			} else {
				fmt.Println("[-] Target function execution reported failure (returned zero).")
			}
		}
	}

	// 10. Cleanup (Handled by defer)
	fmt.Println("[+] Reflective loading process finished.")
	// The deferred VirtualFree will run when main exits.

	// Optional: Keep console open to see output/calc
	// fmt.Println("[*] Press Enter to free the DLL memory and exit...")
	// fmt.Scanln()
}

// --- Helper Functions ---

// processRelocations applies base relocations if the DLL was loaded at a different address
func processRelocations(dllBase uintptr, relocDirRVA uint32, relocDirSize uint32, delta int64) {
	if delta == 0 {
		fmt.Println("    [*] Delta is zero, no relocations needed.")
		return
	}

	relocBlockAddr := dllBase + uintptr(relocDirRVA)       // Absolute address of first relocation block
	maxRelocAddr := relocBlockAddr + uintptr(relocDirSize) // Boundary check
	totalFixups := 0

	for relocBlockAddr < maxRelocAddr {
		relocBlock := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(relocBlockAddr))

		// Check for empty or invalid block
		if relocBlock.VirtualAddress == 0 || relocBlock.SizeOfBlock == 0 {
			fmt.Println("    [*] Encountered zero block, stopping relocation processing.")
			break
		}

		// Calculate number of relocation entries in this block
		// Header is 8 bytes, each entry is 2 bytes (WORD)
		numEntries := (relocBlock.SizeOfBlock - 8) / 2
		fmt.Printf("    [*] Relocation Block: Page RVA=0x%X, Block Size=0x%X, Entries=%d\n",
			relocBlock.VirtualAddress, relocBlock.SizeOfBlock, numEntries)

		// Pointer to the first relocation entry (immediately follows the header)
		entryPtr := relocBlockAddr + unsafe.Sizeof(IMAGE_BASE_RELOCATION{})
		blockFixups := 0

		for i := uint32(0); i < numEntries; i++ {
			entry := *(*uint16)(unsafe.Pointer(entryPtr + uintptr(i*2))) // Read the 2-byte entry
			relocType := entry >> 12                                     // Top 4 bits determine the type
			relocOffset := entry & 0xFFF                                 // Bottom 12 bits are the offset from Page RVA

			// We only care about relocations for our architecture (64-bit)
			if relocType == IMAGE_REL_BASED_DIR64 {
				// Calculate the absolute address that needs patching
				fixAddr := dllBase + uintptr(relocBlock.VirtualAddress) + uintptr(relocOffset)

				// Read the original 64-bit value at the address
				originalValue := *(*uint64)(unsafe.Pointer(fixAddr))

				// Apply the delta and write the new value back
				// Note: Use WriteProcessMemory if direct write fails due to permissions,
				// but it should work since we allocated RWX.
				newValue := uint64(int64(originalValue) + delta)
				*(*uint64)(unsafe.Pointer(fixAddr)) = newValue

				// fmt.Printf("        [+] Applied DIR64 fixup at offset 0x%X (VA 0x%X): 0x%X -> 0x%X\n", relocOffset, fixAddr, originalValue, newValue)
				blockFixups++
				totalFixups++
			} else if relocType != 0 { // Type 0 is padding (IMAGE_REL_BASED_ABSOLUTE)
				fmt.Printf("        [!] Warning: Skipping unhandled relocation type %d at offset 0x%X\n", relocType, relocOffset)
			}
		}
		fmt.Printf("    [*] Applied %d fixups in this block.\n", blockFixups)

		// Move to the next relocation block
		if relocBlock.SizeOfBlock == 0 { // Avoid infinite loop on malformed data
			fmt.Println("    [-] Error: SizeOfBlock is zero, cannot advance.")
			break
		}
		relocBlockAddr += uintptr(relocBlock.SizeOfBlock)
	}

	fmt.Printf("[+] Relocations processing complete. Total fixups applied: %d\n", totalFixups)
}
