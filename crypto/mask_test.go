package crypto

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

func TestMaskLine(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "password simple my_secret_pass",
			expected: "password simple [MASKED]",
		},
		{
			input:    "password simple \"my_secret_pass\"",
			expected: "password simple [MASKED]",
		},
		{
			input:    "password simple 'my_secret_pass'",
			expected: "password simple [MASKED]",
		},
		{
			input:    "password cipher $c$3$g+12345/abc",
			expected: "password cipher [MASKED]",
		},
		{
			input:    "password 7 0822455R31",
			expected: "password 7 [MASKED]",
		},
		{
			input:    "secret 5 $1$mERG$abcdefg",
			expected: "secret 5 [MASKED]",
		},
		{
			input:    "secret 5 \"$1$mERG$abcdefg\"",
			expected: "secret 5 [MASKED]",
		},
		{
			input:    "snmp-agent community read cipher public_key_here",
			expected: "snmp-agent community read cipher [MASKED]",
		},
		{
			input:    "snmp-agent community read cipher \"public_key_here\"",
			expected: "snmp-agent community read cipher [MASKED]",
		},
		{
			input:    "snmp-agent community write cipher private_key_here",
			expected: "snmp-agent community write cipher [MASKED]",
		},
		{
			input:    "key-string cipher $c$3$xyz",
			expected: "key-string cipher [MASKED]",
		},
		{
			input:    "key-string cipher \"$c$3$xyz\"",
			expected: "key-string cipher [MASKED]",
		},
		{
			input:    "key hex 0123456789abcdef",
			expected: "key hex [MASKED]",
		},
		{
			input:    "key hex \"0123456789abcdef\"",
			expected: "key hex [MASKED]",
		},
		// Non-sensitive lines should not be matched
		{
			input:    "interface GigabitEthernet1/0/1",
			expected: "interface GigabitEthernet1/0/1",
		},
		{
			input:    "description link to core switch with password in description",
			expected: "description link to core switch with password in description",
		},
	}

	for _, test := range tests {
		result := MaskLine(test.input)
		if result != test.expected {
			t.Errorf("MaskLine(%q) = %q; expected %q", test.input, result, test.expected)
		}
	}
}

func TestMaskingReader(t *testing.T) {
	inputConfig := `sysname Core-Switch
#
snmp-agent community read cipher public_key
password cipher secret_pass_123
#
interface GigabitEthernet1/0/1
 port link-type trunk
#
key-string cipher xyz
`

	expectedOutput := `sysname Core-Switch
#
snmp-agent community read cipher [MASKED]
password cipher [MASKED]
#
interface GigabitEthernet1/0/1
 port link-type trunk
#
key-string cipher [MASKED]
`

	reader := NewMaskingReader(strings.NewReader(inputConfig))
	var buf bytes.Buffer
	_, err := io.Copy(&buf, reader)
	if err != nil {
		t.Fatalf("failed to read from MaskingReader: %v", err)
	}

	result := buf.String()
	if result != expectedOutput {
		t.Errorf("MaskingReader output mismatch.\nGot:\n%s\nExpected:\n%s", result, expectedOutput)
	}
}

func TestDualStreamPipeline(t *testing.T) {
	rawConfig := []byte(`sysname H3C-Core-Switch
#
snmp-agent community read cipher public_read_comm_123
password cipher my_super_secret_admin_pass_456
#
interface Ten-GigabitEthernet1/0/1
 port link-type trunk
#
key-string cipher secret_key_789
`)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// === Branch 1: E2EE raw stream ===
	encryptedPacket, err := EncryptConfig(rawConfig, key)
	if err != nil {
		t.Fatalf("failed to encrypt raw config: %v", err)
	}

	// Verify decryption yields original plaintext config (with credentials)
	decryptedConfig, err := DecryptConfig(encryptedPacket, key)
	if err != nil {
		t.Fatalf("failed to decrypt packet: %v", err)
	}
	if !bytes.Equal(decryptedConfig, rawConfig) {
		t.Errorf("decrypted config does not match original config")
	}

	// === Branch 2: Cloud Masked stream ===
	maskReader := NewMaskingReader(bytes.NewReader(rawConfig))
	
	// Compress with gzip
	var gzipBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuf)
	_, err = io.Copy(gzipWriter, maskReader)
	if err != nil {
		t.Fatalf("failed to write to gzip: %v", err)
	}
	gzipWriter.Close()

	// Decompress and verify
	gzipReader, err := gzip.NewReader(&gzipBuf)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzipReader.Close()

	var decompressedBuf bytes.Buffer
	_, err = io.Copy(&decompressedBuf, gzipReader)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	expectedMaskedOutput := `sysname H3C-Core-Switch
#
snmp-agent community read cipher [MASKED]
password cipher [MASKED]
#
interface Ten-GigabitEthernet1/0/1
 port link-type trunk
#
key-string cipher [MASKED]
`

	if decompressedBuf.String() != expectedMaskedOutput {
		t.Errorf("dual-stream masked output mismatch.\nGot:\n%s\nExpected:\n%s", decompressedBuf.String(), expectedMaskedOutput)
	}
}

