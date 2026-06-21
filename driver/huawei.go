package driver

import (
	"xconf-agent/config"
)

// HuaweiDriver implements DeviceDriver for Huawei switches and routers
type HuaweiDriver struct{}

// FetchConfig retrieves configuration from Huawei devices
func (hw *HuaweiDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
