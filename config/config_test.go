package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xconf-agent/logger"
)

func TestConfigLoadSave(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "xconf-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.yaml")

	// 1. Save Config
	mockKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex characters
	cfg := &Config{
		TenantID: "tenant-abc",
		AgentID:  "agent-123",
		AgentKey: mockKey,
		Devices: []Device{
			{
				ID:       "dev-1",
				Name:     "Switch 1",
				IP:       "192.168.1.1",
				Port:     22,
				Vendor:   "cisco",
				Username: "admin",
				Password: "env:MOCK_DEVICE_PASSWORD",
				Schedule: "0 2 * * *",
			},
			{
				ID:       "dev-2",
				Name:     "Switch 2",
				IP:       "192.168.1.2",
				Port:     22,
				Vendor:   "h3c",
				Username: "admin",
				Password: "plaintext_password_here",
				Schedule: "",
			},
		},
	}

	err = SaveConfig(configPath, cfg)
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Verify README files exist in the same directory as config
	enReadme := filepath.Join(tempDir, "README.txt")
	zhReadme := filepath.Join(tempDir, "README_zh.txt")
	if _, err := os.Stat(enReadme); err != nil {
		t.Errorf("expected README.txt to exist: %v", err)
	}
	if _, err := os.Stat(zhReadme); err != nil {
		t.Errorf("expected README_zh.txt to exist: %v", err)
	}

	// Verify permissions on Unix
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("failed to stat config file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got: %o", perm)
	}

	// 2. Load Config
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.TenantID != cfg.TenantID || loaded.AgentID != cfg.AgentID || loaded.AgentKey != cfg.AgentKey {
		t.Errorf("loaded config does not match saved config")
	}

	if len(loaded.Devices) != 2 {
		t.Fatalf("expected 2 devices, got: %d", len(loaded.Devices))
	}

	// 3. Resolve Passwords
	// env password
	os.Setenv("MOCK_DEVICE_PASSWORD", "super_secret_env_pass")
	defer os.Unsetenv("MOCK_DEVICE_PASSWORD")

	if loaded.Devices[0].GetResolvedPassword() != "super_secret_env_pass" {
		t.Errorf("expected env password resolution to yield 'super_secret_env_pass', got %q", loaded.Devices[0].GetResolvedPassword())
	}

	// plaintext password
	if loaded.Devices[1].GetResolvedPassword() != "plaintext_password_here" {
		t.Errorf("expected plaintext password, got %q", loaded.Devices[1].GetResolvedPassword())
	}

	// 4. Key Validation Tests
	_, err = ValidateKey(mockKey)
	if err != nil {
		t.Errorf("expected valid key to pass validation: %v", err)
	}

	// Bad key length
	_, err = ValidateKey("too-short")
	if err == nil {
		t.Error("expected error for short key but got nil")
	}

	// Non-hex chars
	_, err = ValidateKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeZ")
	if err == nil {
		t.Error("expected error for non-hex chars but got nil")
	}

	// 5. Logger Sandbox Test
	logger.Log(logger.LevelInfo, "test", "", "Hello sandbox log")
	logPath := filepath.Join(tempDir, "data", "agent.log")
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("expected sandbox log file to exist at %s: %v", logPath, err)
	} else {
		content, _ := os.ReadFile(logPath)
		if !strings.Contains(string(content), "Hello sandbox log") {
			t.Errorf("expected log file to contain 'Hello sandbox log', got: %s", string(content))
		}
	}
}
