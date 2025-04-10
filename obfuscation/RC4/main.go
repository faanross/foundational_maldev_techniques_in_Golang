package main

import (
	"bytes"
	"crypto/rc4"
	"fmt"
)

// RC4-encrypt data with a given key
// Renamed shellcode -> data for generality
func rc4EncryptData(data, key []byte) ([]byte, error) {
	// Create a new RC4 cipher. Keys can be 1 to 256 bytes.
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		// Wrap error for more context
		return nil, fmt.Errorf("rc4: error creating cipher: %w", err)
	}

	// Allocate buffer for the output
	encrypted := make([]byte, len(data))

	// XORKeyStream applies the RC4 keystream to the data.
	// It modifies the 'encrypted' slice in place.
	cipher.XORKeyStream(encrypted, data)

	return encrypted, nil
}

// RC4-decrypt data with a given key
// RC4 encryption and decryption are the same operation.
func rc4DecryptData(encryptedData, key []byte) ([]byte, error) {
	// Just call the encryption function, passing the encrypted data as input.
	// The XOR operation reverses itself when applied with the same keystream.
	return rc4EncryptData(encryptedData, key)
}

func main() {
	// Example data (previously shellcode)
	data := []byte{
		0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
		0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	}

	// RC4 key (can be 1 to 256 bytes long)
	key := []byte("a_secret_rc4_key_123!") // Example key

	fmt.Printf("Original data (%d bytes) : %x\n", len(data), data)
	fmt.Printf("Using RC4 key (%d bytes)  : %s\n", len(key), key) // WARNING: Avoid printing keys in production!

	// Encrypt the data
	encrypted, err := rc4EncryptData(data, key)
	if err != nil {
		fmt.Println("RC4 encryption failed:", err)
		return
	}

	fmt.Printf("Encrypted data (%d bytes): %x\n", len(encrypted), encrypted)

	// Decrypt the data
	decrypted, err := rc4DecryptData(encrypted, key)
	if err != nil {
		fmt.Println("RC4 decryption failed:", err)
		return
	}

	fmt.Printf("Decrypted data (%d bytes): %x\n", len(decrypted), decrypted)

	// --- Verification Step ---
	if bytes.Equal(data, decrypted) {
		fmt.Println("\nVerification successful: Original and decrypted data match.")
	} else {
		fmt.Println("\nVerification FAILED: Original and decrypted data differ.")
		fmt.Printf("Original : %x\n", data)
		fmt.Printf("Decrypted: %x\n", decrypted)
	}
}
