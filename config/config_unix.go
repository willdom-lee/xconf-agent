//go:build !windows

package config

import (
	"os"
)

// HardenConfigPermissions hardens the configuration file permissions to 0600 on Unix-like systems.
func HardenConfigPermissions(path string) error {
	return os.Chmod(path, 0600)
}

// GetDefaultConfigPath returns the default configuration path on Unix-like systems.
func GetDefaultConfigPath() string {
	return "config.yaml"
}
