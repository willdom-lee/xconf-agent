package driver

import (
	"xconf-agent/config"
)

// FortinetDriver implements DeviceDriver for Fortinet firewall devices
type FortinetDriver struct{}

// FetchConfig retrieves configuration from Fortinet devices
func (fn *FortinetDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
