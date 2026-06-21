package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	plaintext := []byte("hostname core-switch-h3c\ninterface GigabitEthernet1/0/1\nport link-type trunk")

	// 1. Success case
	packet, err := EncryptConfig(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	decrypted, err := DecryptConfig(packet, key)
	if err != nil {
		t.Fatalf("DecryptConfig failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted content does not match original: got %q, expected %q", decrypted, plaintext)
	}

	// 2. Invalid Key Size
	badKey := make([]byte, 16)
	_, err = EncryptConfig(plaintext, badKey)
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize, got: %v", err)
	}

	_, err = DecryptConfig(packet, badKey)
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize, got: %v", err)
	}

	// 3. Wrong Key Decryption
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xff // different from key
	_, err = DecryptConfig(packet, wrongKey)
	if err == nil {
		t.Error("expected decryption failure with wrong key, but got no error")
	}

	// 4. Invalid Magic Byte
	corruptedPacket := make([]byte, len(packet))
	copy(corruptedPacket, packet)
	corruptedPacket[0] = 'Y' // Corrupting magic
	_, err = DecryptConfig(corruptedPacket, key)
	if err != ErrInvalidMagic {
		t.Errorf("expected ErrInvalidMagic, got: %v", err)
	}

	// 5. Unsupported Version
	corruptedPacket2 := make([]byte, len(packet))
	copy(corruptedPacket2, packet)
	corruptedPacket2[5] = 0x02 // unsupported version
	_, err = DecryptConfig(corruptedPacket2, key)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion, got: %v", err)
	}

	// 6. Ciphertext Too Short
	shortPacket := packet[:HeaderSize-1]
	_, err = DecryptConfig(shortPacket, key)
	if err != ErrCiphertextTooShort {
		t.Errorf("expected ErrCiphertextTooShort, got: %v", err)
	}
}
