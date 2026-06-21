package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"xconf-agent/config"
	"xconf-agent/crypto"
	"xconf-agent/driver"
	"xconf-agent/logger"
	"xconf-agent/storage"
)

func executeDeviceBackup(sm *storage.StorageManager, dev *config.Device, commandID string) {
	logger.Info("backup", dev.ID, "Starting config backup (%s)...", dev.Name)
	
	drv, err := driver.GetDriver(dev.Vendor, dev.IP)
	if err != nil {
		errMsg := fmt.Sprintf("Driver error: %v", err)
		logger.Error("backup", dev.ID, "%s", errMsg)
		_ = sm.ReportFailure(dev.ID, commandID, errMsg)
		return
	}

	// 1. Fetch raw plaintext config
	plaintext, err := drv.FetchConfig(dev)
	if err != nil {
		errMsg := fmt.Sprintf("SSH collection failed: %v", err)
		logger.Error("backup", dev.ID, "%s", errMsg)
		_ = sm.ReportFailure(dev.ID, commandID, errMsg)
		return
	}

	// 2. Branch 1: E2EE Encrypt
	keyBytes, err := config.ValidateKey(sm.AgentKey())
	if err != nil {
		errMsg := fmt.Sprintf("Key validation failed: %v", err)
		logger.Error("backup", dev.ID, "%s", errMsg)
		_ = sm.ReportFailure(dev.ID, commandID, errMsg)
		return
	}
	rawEnc, err := crypto.EncryptConfig(plaintext, keyBytes)
	if err != nil {
		errMsg := fmt.Sprintf("E2EE encryption failed: %v", err)
		logger.Error("backup", dev.ID, "%s", errMsg)
		_ = sm.ReportFailure(dev.ID, commandID, errMsg)
		return
	}

	// 3. Branch 2: Stream Mask & Gzip
	maskReader := crypto.NewMaskingReader(bytes.NewReader(plaintext))
	var gzipBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuf)
	_, err = io.Copy(gzipWriter, maskReader)
	if err != nil {
		errMsg := fmt.Sprintf("Stream masking failed: %v", err)
		logger.Error("backup", dev.ID, "%s", errMsg)
		_ = sm.ReportFailure(dev.ID, commandID, errMsg)
		return
	}
	gzipWriter.Close()

	// 4. Upload dual-stream
	err = sm.UploadBackup(dev.ID, rawEnc, gzipBuf.Bytes(), commandID)
	if err != nil {
		logger.Error("backup", dev.ID, "Upload failed: %v", err)
	} else {
		logger.Success("backup", dev.ID, "Config backup uploaded successfully.")
	}
}
