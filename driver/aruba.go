package driver

import (
	"xconf-agent/config"
)

// ArubaDriver implements DeviceDriver for Aruba switches
type ArubaDriver struct{}

// FetchConfig retrieves configuration from Aruba devices
func (ab *ArubaDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
