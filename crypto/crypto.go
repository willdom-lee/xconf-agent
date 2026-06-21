package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MagicBytes is the header signature to identify XConf files
	MagicBytes = "XCONF"
	// Version of the current backup package format
	Version = 0x01
	// Flags reserved for future usage
	Flags = 0x00
	// NonceSize is the standard GCM nonce length
	NonceSize = 12
	// HeaderSize represents the exact size of the binary header layout (5 + 1 + 1 + 12 + 4)
	HeaderSize = 5 + 1 + 1 + NonceSize + 4 // 23 bytes
)

var (
	ErrInvalidKeySize     = errors.New("invalid key size: must be exactly 32 bytes (256 bits)")
	ErrInvalidMagic       = errors.New("invalid file header: missing magic signature")
	ErrUnsupportedVersion = errors.New("unsupported backup format version")
	ErrInvalidCipherLen   = errors.New("invalid ciphertext length in header")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// EncryptConfig encrypts plaintext config using AES-256-GCM and wraps it in a custom binary layout
func EncryptConfig(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	cipherLen := uint32(len(ciphertext))

	// Allocate buffer for complete package
	packet := make([]byte, HeaderSize+cipherLen)

	// Build header
	copy(packet[0:5], MagicBytes)
	packet[5] = Version
	packet[6] = Flags
	copy(packet[7:19], nonce)
	binary.BigEndian.PutUint32(packet[19:23], cipherLen)

	// Build payload
	copy(packet[23:], ciphertext)

	return packet, nil
}

// DecryptConfig decrypts the binary packet using AES-256-GCM and returns the plaintext config
func DecryptConfig(packet []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	if len(packet) < HeaderSize {
		return nil, ErrCiphertextTooShort
	}

	// Parse header
	magic := string(packet[0:5])
	if magic != MagicBytes {
		return nil, ErrInvalidMagic
	}

	version := packet[5]
	if version != Version {
		return nil, fmt.Errorf("%w: expected 0x%02x, got 0x%02x", ErrUnsupportedVersion, Version, version)
	}

	// packet[6] is flags (reserved), not used currently

	nonce := packet[7:19]
	cipherLen := binary.BigEndian.Uint32(packet[19:23])

	if len(packet) != HeaderSize+int(cipherLen) {
		return nil, ErrInvalidCipherLen
	}

	ciphertext := packet[23:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext (possibly wrong key or corrupted data): %w", err)
	}

	return plaintext, nil
}
