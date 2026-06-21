package driver

import (
	"xconf-agent/config"
)

// RuijieDriver implements DeviceDriver for Ruijie switches and routers
type RuijieDriver struct{}

// FetchConfig retrieves configuration from Ruijie devices
func (rj *RuijieDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
