package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xconf-agent/crypto"
)

func TestIntegrationCLI(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "xconf-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Build the binary
	binaryPath := filepath.Join(tempDir, "xconf-agent")
	cmdBuild := exec.Command("go", "build", "-o", binaryPath, ".")
	cmdBuild.Dir = "."
	var errBuf bytes.Buffer
	cmdBuild.Stderr = &errBuf
	if err := cmdBuild.Run(); err != nil {
		t.Fatalf("failed to compile agent: %v (stderr: %s)", err, errBuf.String())
	}

	// 2. Test Version Command
	cmdVer := exec.Command(binaryPath, "version")
	outVer, err := cmdVer.Output()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	if !strings.Contains(string(outVer), "XConf Agent v1.0.0") {
		t.Errorf("version output incorrect: %s", string(outVer))
	}

	// 3. Test Install Command
	// Start mock http server for verification
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/functions/v1/xconf-api/verify-install-token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tenant_id":"d3b07384-d113-4ae3-a5d1-d2c679a957a5","supabase_url":"http://localhost:54321"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Generate mock JWT token pointing to the mock server as issuer
	payload := fmt.Sprintf(`{"iss":"%s","app_metadata":{"tenant_id":"d3b07384-d113-4ae3-a5d1-d2c679a957a5"}}`, ts.URL)
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mockToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + payloadEncoded + ".signature"

	mockKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	configPath := filepath.Join(tempDir, "config.yaml")

	cmdInst := exec.Command(binaryPath, "install", "--token="+mockToken, "--key="+mockKey, "--config="+configPath)
	outInst, err := cmdInst.CombinedOutput()
	if err != nil {
		t.Fatalf("install command failed: %v, output: %s", err, string(outInst))
	}
	if !strings.Contains(string(outInst), "d3b07384-d113-4ae3-a5d1-d2c679a957a5") {
		t.Errorf("install output did not contain tenant ID: %s", string(outInst))
	}

	// Check if config.yaml exists
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("config file was not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("config file permission is not 0600, got %o", info.Mode().Perm())
	}

	// 4. Test Check Command
	cmdCheck := exec.Command(binaryPath, "check", "--config="+configPath)
	outCheck, err := cmdCheck.CombinedOutput()
	if err != nil {
		t.Fatalf("check command failed: %v, output: %s", err, string(outCheck))
	}
	if !strings.Contains(string(outCheck), "Config File Load: SUCCESS") {
		t.Errorf("check command report incorrect: %s", string(outCheck))
	}

	// 5. Test Decrypt Command
	// Encrypt a mock configuration text using the crypto package
	plaintext := []byte("hostname branch-router-cisco\ninterface FastEthernet0/0\nip address 10.0.0.1 255.255.255.0")
	keyBytes, _ := hex.DecodeString(mockKey)
	packet, err := crypto.EncryptConfig(plaintext, keyBytes)
	if err != nil {
		t.Fatalf("failed to encrypt mock config: %v", err)
	}

	encryptedPath := filepath.Join(tempDir, "backup.raw.enc")
	if err := os.WriteFile(encryptedPath, packet, 0600); err != nil {
		t.Fatalf("failed to write encrypted backup: %v", err)
	}

	// Run decrypt CLI
	cmdDec := exec.Command(binaryPath, "decrypt", "--file="+encryptedPath, "--key="+mockKey)
	outDec, err := cmdDec.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt command failed: %v, output: %s", err, string(outDec))
	}

	if !strings.Contains(string(outDec), "branch-router-cisco") {
		t.Errorf("decrypted output did not contain expected plaintext: %s", string(outDec))
	}
}

func TestDaemonCLI(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "xconf-daemon-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	binaryPath := filepath.Join(tempDir, "xconf-agent")
	cmdBuild := exec.Command("go", "build", "-o", binaryPath, ".")
	cmdBuild.Stderr = os.Stderr
	if err := cmdBuild.Run(); err != nil {
		t.Fatalf("failed to compile agent: %v", err)
	}

	mockKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	configPath := filepath.Join(tempDir, "config.yaml")
	cfgContent := `tenant_id: "test-tenant-123"
agent_id: "agent-abc"
agent_key: "` + mockKey + `"
supabase_url: "http://localhost:54321"
devices: []
`
	if err := os.WriteFile(configPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmdRun := exec.Command(binaryPath, "run", "--config="+configPath)
	var outBuf bytes.Buffer
	cmdRun.Stdout = &outBuf
	cmdRun.Stderr = &outBuf

	if err := cmdRun.Start(); err != nil {
		t.Fatalf("failed to start daemon process: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if err := cmdRun.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("failed to send SIGINT: %v", err)
	}

	err = cmdRun.Wait()
	if err != nil {
		t.Logf("wait status: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Starting XConf Agent daemon") {
		t.Errorf("daemon did not print startup line: %s", output)
	}
	if !strings.Contains(output, "Stopping XConf Agent service gracefully") {
		t.Errorf("daemon did not print graceful shutdown line: %s", output)
	}
}

