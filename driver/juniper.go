package driver

import (
	"xconf-agent/config"
)

// JuniperDriver implements DeviceDriver for Juniper router/switch devices
type JuniperDriver struct{}

// FetchConfig retrieves configuration from Juniper devices
func (jn *JuniperDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
