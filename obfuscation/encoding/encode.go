package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Base64 encoding/decoding
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// Base85 encoding/decoding (using ASCII85 which is a common Base85 variant)
func encodeBase85(data []byte) string {
	buf := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	encoder.Write(data)
	encoder.Close()
	// This is a simple approximation as Go's standard library doesn't include Base85
	// For a real Base85 implementation, you'd want to use a dedicated library
	return fmt.Sprintf("Base85 approximation: %s", buf.String())
}

// Hex encoding/decoding
func encodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

func decodeHex(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}

// Gob encoding/decoding
func encodeGob(data []byte) (string, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return "", err
	}
	// Convert to hex for display since gob is binary
	return hex.EncodeToString(buf.Bytes()), nil
}

func decodeGob(encoded string) ([]byte, error) {
	// First convert from hex back to binary
	gobBytes, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(gobBytes)
	dec := gob.NewDecoder(buf)

	var result []byte
	if err := dec.Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// Custom base64 encoding with alternative alphabet
func customBase64Encode(data []byte, customAlphabet string) string {
	// Create a custom encoding
	encoding := base64.NewEncoding(customAlphabet).WithPadding(base64.StdPadding)
	return encoding.EncodeToString(data)
}

func customBase64Decode(encodedStr string, customAlphabet string) ([]byte, error) {
	// Create a custom encoding
	encoding := base64.NewEncoding(customAlphabet).WithPadding(base64.StdPadding)
	return encoding.DecodeString(encodedStr)
}

// Simple custom encoding function - Rolling XOR with position
func customRollingXOREncode(data []byte) string {
	key := byte(0x42) // Starting key
	result := make([]byte, len(data))

	for i, b := range data {
		// XOR the byte with a key that changes based on position
		encodedByte := b ^ (key + byte(i%256))
		result[i] = encodedByte
	}

	// Convert to hex for display
	return hex.EncodeToString(result)
}

func customRollingXORDecode(encoded string) ([]byte, error) {
	// Convert from hex back to bytes
	encBytes, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	key := byte(0x42) // Same starting key
	result := make([]byte, len(encBytes))

	for i, b := range encBytes {
		// Reverse the XOR operation with the same position-based key
		decodedByte := b ^ (key + byte(i%256))
		result[i] = decodedByte
	}

	return result, nil
}

func main() {
	fmt.Println("Enter text to encode (or press Enter to use example shellcode):")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var data []byte

	if input == "" {
		// Example shellcode if no input provided
		data = []byte{
			0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
			0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
		}
		fmt.Println("Using example shellcode")
	} else {
		data = []byte(input)
		fmt.Println("Using your input:", input)
	}

	fmt.Println("\nOriginal data (hex):", hex.EncodeToString(data))

	// Standard Base64 encoding
	base64Encoded := encodeBase64(data)
	fmt.Println("\n1. Base64 Encoded:")
	fmt.Println(base64Encoded)

	// Base85 (ASCII85) approximation
	base85Encoded := encodeBase85(data)
	fmt.Println("\n2. Base85 Approximation:")
	fmt.Println(base85Encoded)

	// Hex encoding
	hexEncoded := encodeHex(data)
	fmt.Println("\n3. Hex Encoded:")
	fmt.Println(hexEncoded)

	// Gob encoding
	gobEncoded, err := encodeGob(data)
	if err != nil {
		fmt.Println("Error encoding with Gob:", err)
	} else {
		fmt.Println("\n4. Gob Encoded (displayed as hex):")
		fmt.Println(gobEncoded)
	}

	// Custom Base64 alphabet
	customAlphabet := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
	customBase64Encoded := customBase64Encode(data, customAlphabet)
	fmt.Println("\n5. Custom Base64 Alphabet:")
	fmt.Println(customBase64Encoded)

	// Custom rolling XOR encoding
	rollingXOREncoded := customRollingXOREncode(data)
	fmt.Println("\n6. Custom Rolling XOR Encoding (displayed as hex):")
	fmt.Println(rollingXOREncoded)

	// Demonstrate decoding
	fmt.Println("\n--- Decoding Demonstration ---")

	// Base64 decoding
	base64Decoded, _ := decodeBase64(base64Encoded)
	fmt.Println("\nBase64 Decoded:", hex.EncodeToString(base64Decoded))

	// Hex decoding
	hexDecoded, _ := decodeHex(hexEncoded)
	fmt.Println("Hex Decoded:", hex.EncodeToString(hexDecoded))

	// Gob decoding
	gobDecoded, err := decodeGob(gobEncoded)
	if err != nil {
		fmt.Println("Error decoding with Gob:", err)
	} else {
		fmt.Println("Gob Decoded:", hex.EncodeToString(gobDecoded))
	}

	// Custom Base64 decoding
	customBase64Decoded, _ := customBase64Decode(customBase64Encoded, customAlphabet)
	fmt.Println("Custom Base64 Decoded:", hex.EncodeToString(customBase64Decoded))

	// Custom rolling XOR decoding
	rollingXORDecoded, _ := customRollingXORDecode(rollingXOREncoded)
	fmt.Println("Rolling XOR Decoded:", hex.EncodeToString(rollingXORDecoded))

	// Verify all decodings match the original
	allMatched := bytes.Equal(data, base64Decoded) &&
		bytes.Equal(data, hexDecoded) &&
		bytes.Equal(data, gobDecoded) &&
		bytes.Equal(data, customBase64Decoded) &&
		bytes.Equal(data, rollingXORDecoded)

	if allMatched {
		fmt.Println("\nAll decodings successfully match the original data! ✓")
	} else {
		fmt.Println("\nWarning: Not all decodings match the original data.")
	}
}
