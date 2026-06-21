package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"xconf-agent/config"
	"xconf-agent/logger"
)

// UploadUrlsResponse holds S3 pre-signed upload URLs and storage paths
type UploadUrlsResponse struct {
	RawUploadURL        string `json:"raw_upload_url"`
	RawStoragePath      string `json:"raw_storage_path"`
	MaskedUploadURL     string `json:"masked_upload_url"`
	MaskedStoragePath   string `json:"masked_storage_path"`
	LocalRetentionLimit *int   `json:"local_retention_limit"`
}

// GetUploadUrlRequest is the request payload to retrieve pre-signed URLs
type GetUploadUrlRequest struct {
	AgentID             string `json:"agent_id"`
	DeviceID            string `json:"device_id"`
	DeviceName          string `json:"device_name"`
	IP                  string `json:"ip"`
	Vendor              string `json:"vendor"`
	RawFileSizeBytes    int64  `json:"raw_file_size_bytes"`
	MaskedFileSizeBytes int64  `json:"masked_file_size_bytes"`
}

// ReportCompleteRequest reports the final outcome of the double-stream backup
type ReportCompleteRequest struct {
	CommandID         string `json:"command_id,omitempty"`
	DeviceID          string `json:"device_id"`
	RawStoragePath    string `json:"raw_storage_path"`
	RawFileSize       int64  `json:"raw_file_size_bytes"`
	MaskedStoragePath string `json:"masked_storage_path"`
	MaskedFileSize    int64  `json:"masked_file_size_bytes"`
	Status            string `json:"status"`
	ResultMessage     string `json:"result_message"`
}

// CommandPayload holds the payload of manual command to run
type CommandPayload struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	IP         string `json:"ip"`
	Vendor     string `json:"vendor"`
}

// CommandResponse holds the response containing the command retrieved from the queue
type CommandResponse struct {
	Command *struct {
		ID          string         `json:"id"`
		CommandType string         `json:"command_type"`
		Payload     CommandPayload `json:"payload"`
	} `json:"command"`
}


// HeartbeatDevice reports minimal device metadata during heartbeats
type HeartbeatDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Vendor   string `json:"vendor"`
}

// HeartbeatRequest payload to report agent online status
type HeartbeatRequest struct {
	AgentID      string            `json:"agent_id"`
	AgentVersion string            `json:"agent_version"`
	OSPlatform   string            `json:"os_platform"`
	Devices      []HeartbeatDevice `json:"devices,omitempty"`
}

// HeartbeatResponse holds the parsed response from the heartbeat API
type HeartbeatResponse struct {
	Action    string           `json:"action"`
	Schedules []DeviceSchedule `json:"schedules"`
}

// StorageManager orchestrates local caching, disaster queuing, and cloud uploads
type StorageManager struct {
	cfgMutex     sync.RWMutex
	cfg          *config.Config
	configPath   string
	client       *http.Client
	uploadClient *http.Client
}

// NewStorageManager instantiates a StorageManager
func NewStorageManager(cfg *config.Config, configPath string) *StorageManager {
	return &StorageManager{
		cfg:          cfg,
		configPath:   configPath,
		client:       &http.Client{Timeout: 15 * time.Second},
		uploadClient: &http.Client{Timeout: 120 * time.Second},
	}
}

// UpdateConfig updates the internal configuration reference thread-safely
func (sm *StorageManager) UpdateConfig(cfg *config.Config) {
	sm.cfgMutex.Lock()
	defer sm.cfgMutex.Unlock()
	sm.cfg = cfg
}

// GetConfig retrieves the current configuration snapshot thread-safely
func (sm *StorageManager) GetConfig() *config.Config {
	sm.cfgMutex.RLock()
	defer sm.cfgMutex.RUnlock()
	return sm.cfg
}

// AgentKey returns the agent's key string
func (sm *StorageManager) AgentKey() string {
	return sm.GetConfig().AgentKey
}

// sendAPIRequest posts JSON to a Supabase Edge Function endpoint
func (sm *StorageManager) sendAPIRequest(endpoint string, bodyVal interface{}) ([]byte, error) {
	cfg := sm.GetConfig()
	url := fmt.Sprintf("%s/functions/v1/xconf-api/%s", strings.TrimSuffix(cfg.SupabaseURL, "/"), endpoint)
	
	jsonBytes, err := json.Marshal(bodyVal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-agent-key-hash", sm.agentKeyHash())
	req.Header.Set("x-tenant-id", cfg.TenantID)
	if cfg.SupabaseAnonKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.SupabaseAnonKey)
	}

	resp, err := sm.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

type DeviceSchedule struct {
	ID             string  `json:"id"`
	BackupSchedule *string `json:"backup_schedule"`
}

// SendHeartbeat sends an online status heartbeat report and returns the server response
func (sm *StorageManager) SendHeartbeat() (*HeartbeatResponse, error) {
	cfg := sm.GetConfig()
	var heartbeatDevs []HeartbeatDevice
	for _, d := range cfg.Devices {
		port := d.Port
		if port == 0 {
			if strings.ToLower(d.Protocol) == "telnet" {
				port = 23
			} else {
				port = 22
			}
		}
		heartbeatDevs = append(heartbeatDevs, HeartbeatDevice{
			ID:       d.ID,
			Name:     d.Name,
			IP:       d.IP,
			Port:     port,
			Protocol: d.Protocol,
			Vendor:   d.Vendor,
		})
	}

	body := HeartbeatRequest{
		AgentID:      cfg.AgentID,
		AgentVersion: "1.0.0",
		OSPlatform:   runtime.GOOS + "/" + runtime.GOARCH,
		Devices:      heartbeatDevs,
	}
	respBytes, err := sm.sendAPIRequest("agent-heartbeat", body)
	if err != nil {
		return nil, err
	}

	var resp HeartbeatResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// PollCommands queries the server for any pending command for this agent
func (sm *StorageManager) PollCommands(agentID string) (*CommandResponse, error) {
	reqBody := map[string]string{
		"agent_id": agentID,
	}

	respBytes, err := sm.sendAPIRequest("poll-commands", reqBody)
	if err != nil {
		return nil, err
	}

	var resp CommandResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse command response: %w", err)
	}

	return &resp, nil
}


// UploadBackup runs the dual-stream backup pipeline
func (sm *StorageManager) UploadBackup(deviceID string, rawData []byte, maskedData []byte, commandID string) error {
	// 1. Dumps to latest cache
	sm.saveLatestCache(deviceID, rawData)

	// Save to history cache
	if _, errHist := sm.saveHistoryBackup(deviceID, rawData); errHist != nil {
		logger.Warn("backup", deviceID, "Failed to save history backup locally: %v", errHist)
	}

	cfg := sm.GetConfig()
	// 2. Request pre-signed URLs
	var devName, devIP, devVendor string
	for _, d := range cfg.Devices {
		if d.ID == deviceID {
			devName = d.Name
			devIP = d.IP
			devVendor = d.Vendor
			break
		}
	}
	if devName == "" {
		devName = "Device " + deviceID
	}
	if devIP == "" {
		devIP = "127.0.0.1"
	}
	if devVendor == "" {
		devVendor = "cisco"
	}

	reqBody := GetUploadUrlRequest{
		AgentID:             cfg.AgentID,
		DeviceID:            deviceID,
		DeviceName:          devName,
		IP:                  devIP,
		Vendor:              devVendor,
		RawFileSizeBytes:    int64(len(rawData)),
		MaskedFileSizeBytes: int64(len(maskedData)),
	}

	respBytes, err := sm.sendAPIRequest("get-upload-url", reqBody)
	if err != nil {
		sm.saveToQueue(deviceID, rawData, maskedData)
		return fmt.Errorf("get upload URLs failed (queued locally): %w", err)
	}

	var urls UploadUrlsResponse
	if err := json.Unmarshal(respBytes, &urls); err != nil {
		sm.saveToQueue(deviceID, rawData, maskedData)
		return fmt.Errorf("parse upload URLs failed (queued locally): %w", err)
	}

	// Apply local retention pruning
	sm.pruneHistoryBackups(deviceID, urls.LocalRetentionLimit)

	// 3. HTTP PUT uploads
	errRaw := sm.putFile(urls.RawUploadURL, rawData, "application/octet-stream")
	errMasked := sm.putFile(urls.MaskedUploadURL, maskedData, "application/x-gzip")

	status := "completed"
	resultMsg := "OK"
	if errRaw != nil || errMasked != nil {
		status = "failed"
		resultMsg = fmt.Sprintf("raw_err: %v, masked_err: %v", errRaw, errMasked)
		sm.saveToQueue(deviceID, rawData, maskedData)
	}

	// 4. Report complete status
	reportReq := ReportCompleteRequest{
		CommandID:         commandID,
		DeviceID:          deviceID,
		RawStoragePath:    urls.RawStoragePath,
		RawFileSize:       int64(len(rawData)),
		MaskedStoragePath: urls.MaskedStoragePath,
		MaskedFileSize:    int64(len(maskedData)),
		Status:            status,
		ResultMessage:     resultMsg,
	}

	if _, err := sm.sendAPIRequest("backup-complete", reportReq); err != nil {
		logger.Error("storage", deviceID, "Failed to report backup completion: %v", err)
	}

	if status == "failed" {
		return fmt.Errorf("upload failed: %s", resultMsg)
	}

	return nil
}

// ProcessQueue scans and re-uploads queued backups when network is restored
func (sm *StorageManager) ProcessQueue() {
	cfg := sm.GetConfig()
	queueDir := filepath.Join(filepath.Dir(sm.configPath), "data", "queue")
	files, err := os.ReadDir(queueDir)
	if err != nil {
		return
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".raw.enc") {
			continue
		}

		rawPath := filepath.Join(queueDir, file.Name())
		maskedPath := strings.Replace(rawPath, ".raw.enc", ".masked.gz", 1)

		if _, err := os.Stat(maskedPath); err != nil {
			continue
		}

		name := strings.TrimSuffix(file.Name(), ".raw.enc")
		parts := strings.Split(name, "_")
		if len(parts) < 3 {
			continue
		}
		deviceID := strings.Join(parts[1:len(parts)-1], "_")

		rawData, errRaw := os.ReadFile(rawPath)
		maskedData, errMasked := os.ReadFile(maskedPath)
		if errRaw != nil || errMasked != nil {
			continue
		}

		var devName, devIP, devVendor string
		for _, d := range cfg.Devices {
			if d.ID == deviceID {
				devName = d.Name
				devIP = d.IP
				devVendor = d.Vendor
				break
			}
		}
		if devName == "" {
			devName = "Device " + deviceID
		}
		if devIP == "" {
			devIP = "127.0.0.1"
		}
		if devVendor == "" {
			devVendor = "cisco"
		}

		reqBody := GetUploadUrlRequest{
			AgentID:             cfg.AgentID,
			DeviceID:            deviceID,
			DeviceName:          devName,
			IP:                  devIP,
			Vendor:              devVendor,
			RawFileSizeBytes:    int64(len(rawData)),
			MaskedFileSizeBytes: int64(len(maskedData)),
		}

		respBytes, err := sm.sendAPIRequest("get-upload-url", reqBody)
		if err != nil {
			return // stop processing on network issue
		}

		var urls UploadUrlsResponse
		if err := json.Unmarshal(respBytes, &urls); err != nil {
			continue
		}

		errRawPut := sm.putFile(urls.RawUploadURL, rawData, "application/octet-stream")
		errMaskedPut := sm.putFile(urls.MaskedUploadURL, maskedData, "application/x-gzip")

		status := "completed"
		resultMsg := "OK"
		if errRawPut != nil || errMaskedPut != nil {
			status = "failed"
			resultMsg = fmt.Sprintf("raw_err: %v, masked_err: %v", errRawPut, errMaskedPut)
		}

		reportReq := ReportCompleteRequest{
			DeviceID:          deviceID,
			RawStoragePath:    urls.RawStoragePath,
			RawFileSize:       int64(len(rawData)),
			MaskedStoragePath: urls.MaskedStoragePath,
			MaskedFileSize:    int64(len(maskedData)),
			Status:            status,
			ResultMessage:     resultMsg,
		}

		if _, err := sm.sendAPIRequest("backup-complete", reportReq); err != nil {
			logger.Error("storage", deviceID, "Failed to report backup completion: %v", err)
		}

		if status == "completed" {
			_ = os.Remove(rawPath)
			_ = os.Remove(maskedPath)
			sm.pruneHistoryBackups(deviceID, urls.LocalRetentionLimit)
		} else {
			return // stop queue on upload issue
		}
	}
}

func (sm *StorageManager) saveHistoryBackup(deviceID string, rawData []byte) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	dir := filepath.Join(filepath.Dir(sm.configPath), "data", "history", fmt.Sprintf("dev_%s", deviceID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create history directory: %w", err)
	}
	fileName := fmt.Sprintf("dev_%s_%s.raw.enc", deviceID, timestamp)
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, rawData, 0600); err != nil {
		return "", fmt.Errorf("failed to write history backup file: %w", err)
	}
	return path, nil
}

func (sm *StorageManager) pruneHistoryBackups(deviceID string, limitVal *int) {
	if limitVal == nil {
		logger.Info("pruning", deviceID, "Local backup limit is unlimited (keep all). Skipping pruning.")
		return
	}

	limit := *limitVal
	if limit < 1 {
		return
	}

	dir := filepath.Join(filepath.Dir(sm.configPath), "data", "history", fmt.Sprintf("dev_%s", deviceID))
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backupFiles []os.DirEntry
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), fmt.Sprintf("dev_%s_", deviceID)) && strings.HasSuffix(f.Name(), ".raw.enc") {
			backupFiles = append(backupFiles, f)
		}
	}

	// Sort by filename ascending (which sorts by timestamp because of the YYYYMMDD-HHMMSS suffix)
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].Name() < backupFiles[j].Name()
	})

	if len(backupFiles) <= limit {
		return
	}

	excess := len(backupFiles) - limit
	logger.Info("pruning", deviceID, "Local backup limit reached (limit: %d, current: %d). Cleaning up %d oldest local backup(s).", limit, len(backupFiles), excess)

	for i := 0; i < excess; i++ {
		path := filepath.Join(dir, backupFiles[i].Name())
		if err := os.Remove(path); err != nil {
			logger.Warn("pruning", deviceID, "Failed to delete old backup file %s: %v", path, err)
		} else {
			logger.Info("pruning", deviceID, "Cleaned up oldest local backup: %s", backupFiles[i].Name())
		}
	}
}

func (sm *StorageManager) putFile(uploadURL string, data []byte, contentType string) error {
	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := sm.uploadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT status %d: %s", resp.StatusCode, string(respBytes))
	}

	return nil
}

func (sm *StorageManager) saveLatestCache(deviceID string, rawData []byte) {
	path := filepath.Join(filepath.Dir(sm.configPath), "data", "latest", fmt.Sprintf("dev_%s.raw.enc", deviceID))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		logger.Error("storage", deviceID, "Failed to create latest cache directory: %v", err)
		return
	}
	if err := os.WriteFile(path, rawData, 0600); err != nil {
		logger.Error("storage", deviceID, "Failed to write latest cache file: %v", err)
	}
}

func (sm *StorageManager) saveToQueue(deviceID string, rawData []byte, maskedData []byte) {
	timestamp := time.Now().Format("20060102T150405")
	rawPath := filepath.Join(filepath.Dir(sm.configPath), "data", "queue", fmt.Sprintf("dev_%s_%s.raw.enc", deviceID, timestamp))
	maskedPath := filepath.Join(filepath.Dir(sm.configPath), "data", "queue", fmt.Sprintf("dev_%s_%s.masked.gz", deviceID, timestamp))

	if err := os.MkdirAll(filepath.Dir(rawPath), 0700); err != nil {
		logger.Error("storage", deviceID, "Failed to create queue directory: %v", err)
		return
	}
	if err := os.WriteFile(rawPath, rawData, 0600); err != nil {
		logger.Error("storage", deviceID, "Failed to write raw queue file: %v", err)
	}
	if err := os.WriteFile(maskedPath, maskedData, 0600); err != nil {
		logger.Error("storage", deviceID, "Failed to write masked queue file: %v", err)
	}
}

func (sm *StorageManager) agentKeyHash() string {
	h := sha256.Sum256([]byte(sm.GetConfig().AgentKey))
	return hex.EncodeToString(h[:])
}

// ReportFailure reports a backup failure for manual commands or local driver errors
func (sm *StorageManager) ReportFailure(deviceID string, commandID string, errMsg string) error {
	reportReq := ReportCompleteRequest{
		CommandID:     commandID,
		DeviceID:      deviceID,
		Status:        "failed",
		ResultMessage: errMsg,
	}
	_, err := sm.sendAPIRequest("backup-complete", reportReq)
	return err
}

