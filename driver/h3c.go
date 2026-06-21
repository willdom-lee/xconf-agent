package driver

import (
	"xconf-agent/config"
)

// H3CDriver implements DeviceDriver for H3C switches and routers
type H3CDriver struct{}

// FetchConfig retrieves configuration from H3C devices using the Expect-Regex engine
func (h *H3CDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
