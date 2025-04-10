package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AES-encrypt shellcode with a given key
func aesEncryptShellcode(shellcode, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random IV (Initialization Vector)
	encrypted := make([]byte, aes.BlockSize+len(shellcode))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt the shellcode using CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)

	// Pad the shellcode to be a multiple of the block size
	padding := aes.BlockSize - (len(shellcode) % aes.BlockSize)
	paddedShellcode := make([]byte, len(shellcode)+padding)
	copy(paddedShellcode, shellcode)

	// Add PKCS#7 padding
	for i := len(shellcode); i < len(paddedShellcode); i++ {
		paddedShellcode[i] = byte(padding)
	}

	// Perform the encryption
	mode.CryptBlocks(encrypted[aes.BlockSize:], paddedShellcode)

	return encrypted, nil
}

// AES-decrypt shellcode with a given key
func aesDecryptShellcode(encrypted, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract the IV
	if len(encrypted) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	// Decrypt the shellcode
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// Remove PKCS#7 padding
	padding := int(decrypted[len(decrypted)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify the padding is correct
	for i := len(decrypted) - padding; i < len(decrypted); i++ {
		if decrypted[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return decrypted[:len(decrypted)-padding], nil
}

func main() {
	// Example shellcode
	shellcode := []byte{
		0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
		0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	}

	// AES-256 requires a 32-byte key
	key := []byte("this_is_a_32_byte_key_for_aes_256!")

	// Encrypt the shellcode
	encrypted, err := aesEncryptShellcode(shellcode, key)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}

	fmt.Println("Original shellcode (first few bytes):", shellcode[:8])
	fmt.Println("Encrypted shellcode (first few bytes after IV):", encrypted[aes.BlockSize:aes.BlockSize+8])

	// Decrypt the shellcode
	decrypted, err := aesDecryptShellcode(encrypted, key)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Println("Decrypted shellcode (first few bytes):", decrypted[:8])
}
