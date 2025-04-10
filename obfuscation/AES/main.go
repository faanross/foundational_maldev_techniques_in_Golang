package main

import (
	"bytes" // Import bytes for comparison later
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AES-encrypt shellcode with a given key using CBC and PKCS#7 padding
func aesEncryptShellcode(shellcode, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	// --- Calculate PKCS#7 padding ---
	padding := aes.BlockSize - (len(shellcode) % aes.BlockSize)
	// Create padded buffer. The padding itself is the byte value equal to the padding length.
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedShellcode := append(shellcode, padText...) // Append padding to original shellcode

	// --- Allocate encrypted buffer AFTER knowing padded size ---
	// Need space for IV + padded data
	encrypted := make([]byte, aes.BlockSize+len(paddedShellcode))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("error reading random bytes for IV: %w", err)
	}

	// Encrypt the shellcode using CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)

	// Perform the encryption. Destination and source lengths now match required criteria.
	mode.CryptBlocks(encrypted[aes.BlockSize:], paddedShellcode)

	return encrypted, nil
}

// AES-decrypt shellcode with a given key assuming CBC and PKCS#7 padding
func aesDecryptShellcode(encrypted, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	// Check length before slicing: Must be at least IV size
	if len(encrypted) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short (less than block size)")
	}
	iv := encrypted[:aes.BlockSize]
	ciphertext := encrypted[aes.BlockSize:]

	// Check ciphertext length: Must be a multiple of block size for CBC
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size (%d), length is %d", aes.BlockSize, len(ciphertext))
	}
	// Check ciphertext length: Must not be empty
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}

	// Decrypt the shellcode
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext)) // Allocate based on ciphertext length
	mode.CryptBlocks(decrypted, ciphertext)

	// --- Remove PKCS#7 padding ---
	// Get the last byte, which indicates the padding length
	padding := int(decrypted[len(decrypted)-1])

	// Validate padding value: Must be between 1 and BlockSize
	if padding > aes.BlockSize || padding == 0 {
		// Return a generic error in production to avoid padding oracle attacks
		return nil, fmt.Errorf("invalid padding size: %d", padding)
	}
	// Validate padding value: Padding length cannot be greater than the data length
	if padding > len(decrypted) {
		// Return a generic error in production
		return nil, fmt.Errorf("invalid padding: padding size (%d) larger than data length (%d)", padding, len(decrypted))
	}

	// Verify all padding bytes have the correct value
	padStartIndex := len(decrypted) - padding
	for i := padStartIndex; i < len(decrypted); i++ {
		if decrypted[i] != byte(padding) {
			// Return a generic error in production
			return nil, fmt.Errorf("invalid padding byte detected at index %d", i)
		}
	}

	// Return data excluding the padding
	return decrypted[:padStartIndex], nil
}

func main() {
	// Example shellcode
	shellcode := []byte{
		0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
		0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, // 16 bytes
		// 0x55, // Uncomment to make it 17 bytes and test padding
	}

	// AES-256 requires a 32-byte key
	key := []byte("this_is_a_32_byte_key_for_aes256")

	fmt.Printf("Original shellcode (%d bytes): %x\n", len(shellcode), shellcode)
	fmt.Printf("Using AES key        (%d bytes): %s\n", len(key), key) // Be careful printing keys!

	// Encrypt the shellcode
	encrypted, err := aesEncryptShellcode(shellcode, key)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}

	fmt.Printf("IV + Encrypted (%d bytes): %x\n", len(encrypted), encrypted)
	fmt.Printf("IV (first %d bytes)        : %x\n", aes.BlockSize, encrypted[:aes.BlockSize])
	fmt.Printf("Encrypted data (%d bytes) : %x\n", len(encrypted)-aes.BlockSize, encrypted[aes.BlockSize:])

	// Decrypt the shellcode
	decrypted, err := aesDecryptShellcode(encrypted, key)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Printf("Decrypted shellcode (%d bytes): %x\n", len(decrypted), decrypted)

	// Verify
	if bytes.Equal(shellcode, decrypted) {
		fmt.Println("Verification successful: Original and decrypted shellcode match.")
	} else {
		fmt.Println("Verification FAILED: Original and decrypted shellcode differ.")
	}
}
