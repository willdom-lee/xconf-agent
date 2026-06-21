package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xconf-agent/config"
)

func TestStorageLocalCacheAndQueue(t *testing.T) {
	cfg := &config.Config{
		TenantID: "tenant-123",
		AgentID:  "agent-abc",
		AgentKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	tempDir, err := os.MkdirTemp("", "xconf-storage-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working dir: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to change working dir: %v", err)
	}
	defer os.Chdir(oldWd)

	sm := NewStorageManager(cfg, "config.yaml")

	deviceID := "dev-1"
	rawData := []byte("hostname test\ninterface ge0")
	maskedData := []byte("gzip_mock_data")

	// 1. Test Latest Cache
	sm.saveLatestCache(deviceID, rawData)
	latestPath := filepath.Join("data", "latest", fmt.Sprintf("dev_%s.raw.enc", deviceID))
	info, err := os.Stat(latestPath)
	if err != nil {
		t.Fatalf("latest cache file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permission 0600, got: %o", info.Mode().Perm())
	}
	savedData, _ := os.ReadFile(latestPath)
	if !bytes.Equal(savedData, rawData) {
		t.Errorf("saved data mismatch: %s", string(savedData))
	}

	// 2. Test Save to Queue
	sm.saveToQueue(deviceID, rawData, maskedData)
	queueDir := filepath.Join("data", "queue")
	files, err := os.ReadDir(queueDir)
	if err != nil || len(files) != 2 {
		t.Fatalf("queue files not created correctly, files: %v", files)
	}
	
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		path := filepath.Join(queueDir, file.Name())
		data, _ := os.ReadFile(path)
		if strings.HasSuffix(file.Name(), ".raw.enc") {
			if !bytes.Equal(data, rawData) {
				t.Error("raw queue data mismatch")
			}
		} else if strings.HasSuffix(file.Name(), ".masked.gz") {
			if !bytes.Equal(data, maskedData) {
				t.Error("masked queue data mismatch")
			}
		}
	}
}

func TestStorageUpload(t *testing.T) {
	var getUploadCalled, completeCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		expectedKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		h := sha256.Sum256([]byte(expectedKey))
		expectedHash := hex.EncodeToString(h[:])
		if r.Header.Get("x-agent-key-hash") != expectedHash {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.HasSuffix(r.URL.Path, "get-upload-url") {
			getUploadCalled = true
			resp := UploadUrlsResponse{
				RawUploadURL:      "http://example.com/raw",
				RawStoragePath:    "raw_path",
				MaskedUploadURL:   "http://example.com/masked",
				MaskedStoragePath: "masked_path",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if strings.HasSuffix(r.URL.Path, "backup-complete") {
			completeCalled = true
			var body ReportCompleteRequest
			json.NewDecoder(r.Body).Decode(&body)
			if body.Status != "failed" {
				t.Errorf("expected complete report status to be failed, got: %s", body.Status)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &config.Config{
		TenantID:    "tenant-123",
		AgentID:     "agent-abc",
		AgentKey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SupabaseURL: server.URL,
	}

	tempDir, err := os.MkdirTemp("", "xconf-storage-upload-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	sm := NewStorageManager(cfg, "config.yaml")

	err = sm.UploadBackup("dev-1", []byte("raw"), []byte("masked"), "")
	if err == nil {
		t.Error("expected upload to fail since S3 URL is example.com, but got nil")
	}

	if !getUploadCalled {
		t.Error("expected get-upload-url to be called")
	}
	if !completeCalled {
		t.Error("expected backup-complete to be called")
	}

	queueDir := filepath.Join("data", "queue")
	files, _ := os.ReadDir(queueDir)
	if len(files) != 2 {
		t.Errorf("expected 2 files in queue, got: %d", len(files))
	}
}

func TestStorageUpdateConfig(t *testing.T) {
	cfg1 := &config.Config{
		TenantID: "tenant-1",
		AgentID:  "agent-1",
		AgentKey: "key-1",
	}
	cfg2 := &config.Config{
		TenantID: "tenant-2",
		AgentID:  "agent-2",
		AgentKey: "key-2",
	}

	sm := NewStorageManager(cfg1, "config.yaml")
	if sm.GetConfig().TenantID != "tenant-1" {
		t.Errorf("expected initial tenant-1, got %s", sm.GetConfig().TenantID)
	}

	// Test concurrent read and write to verify race detector doesn't fail
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			_ = sm.GetConfig()
			_ = sm.AgentKey()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.UpdateConfig(cfg2)
		}
		done <- true
	}()

	<-done
	<-done

	if sm.GetConfig().TenantID != "tenant-2" {
		t.Errorf("expected updated tenant-2, got %s", sm.GetConfig().TenantID)
	}
}

