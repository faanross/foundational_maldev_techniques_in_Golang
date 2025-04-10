package main

import (
	"fmt"
)

// Basic XOR encoding with a single-byte key
func basicXorEncode(shellcode []byte, key byte) []byte {
	encoded := make([]byte, len(shellcode))
	for i := 0; i < len(shellcode); i++ {
		encoded[i] = shellcode[i] ^ key
	}
	return encoded
}

// Multi-byte XOR encoding with a key of arbitrary length
func multiByteXorEncode(shellcode []byte, key []byte) []byte {
	encoded := make([]byte, len(shellcode))
	keyLen := len(key)
	for i := 0; i < len(shellcode); i++ {
		encoded[i] = shellcode[i] ^ key[i%keyLen]
	}
	return encoded
}

// Rolling XOR encoding where the key changes with each byte
func rollingXorEncode(shellcode []byte, initialKey byte) []byte {
	encoded := make([]byte, len(shellcode))
	key := initialKey
	for i := 0; i < len(shellcode); i++ {
		encoded[i] = shellcode[i] ^ key
		// Update the key based on the original shellcode byte
		// This makes the encoding more complex to reverse
		key = (key + shellcode[i]) & 0xFF
	}
	return encoded
}

// Corresponding decoder for rolling XOR
func rollingXorDecode(encoded []byte, initialKey byte) []byte {
	decoded := make([]byte, len(encoded))
	key := initialKey
	for i := 0; i < len(encoded); i++ {
		decoded[i] = encoded[i] ^ key
		// Update the key using the decoded byte (original shellcode)
		key = (key + decoded[i]) & 0xFF
	}
	return decoded
}

func main() {
	// Example shellcode (simplified for demonstration)
	shellcode := []byte{
		0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
		0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	}

	// Encode using different XOR techniques
	key := byte(0x37)
	multiKey := []byte{0x37, 0x64, 0x92, 0x15}

	basicEncoded := basicXorEncode(shellcode, key)
	multiEncoded := multiByteXorEncode(shellcode, multiKey)
	rollingEncoded := rollingXorEncode(shellcode, key)

	fmt.Println("Original shellcode (first few bytes):", shellcode[:8])
	fmt.Println("Basic XOR encoded:", basicEncoded[:8])
	fmt.Println("Multi-byte XOR encoded:", multiEncoded[:8])
	fmt.Println("Rolling XOR encoded:", rollingEncoded[:8])

	// Demonstrate decoding
	rollingDecoded := rollingXorDecode(rollingEncoded, key)
	fmt.Println("Rolling XOR decoded:", rollingDecoded[:8])
}
