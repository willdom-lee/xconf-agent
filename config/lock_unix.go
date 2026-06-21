//go:build !windows
// +build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// AcquirePIDLock tries to write a PID file to lock execution to a single instance.
func AcquirePIDLock(configPath string) (func(), error) {
	dir := filepath.Join(filepath.Dir(configPath), "data")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory for PID lock: %w", err)
	}
	lockPath := filepath.Join(dir, "agent.pid")

	// Read existing PID file
	data, err := os.ReadFile(lockPath)
	if err == nil {
		oldPid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil && oldPid > 0 {
			// Check if process exists
			proc, err := os.FindProcess(oldPid)
			if err == nil {
				// Signal 0 checks for process existence without sending any signal
				err = proc.Signal(syscall.Signal(0))
				if err == nil {
					return nil, fmt.Errorf("another agent instance is already running with PID %d (using lock file %s)", oldPid, lockPath)
				}
			}
		}
	}

	// Write current PID
	currentPid := os.Getpid()
	err = os.WriteFile(lockPath, []byte(strconv.Itoa(currentPid)), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write PID lock file %s: %w", lockPath, err)
	}

	cleanup := func() {
		_ = os.Remove(lockPath)
	}
	return cleanup, nil
}
