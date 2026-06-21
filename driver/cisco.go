package driver

import (
	"xconf-agent/config"
)

// CiscoDriver implements DeviceDriver for Cisco switches and routers
type CiscoDriver struct{}

// FetchConfig retrieves configuration from Cisco devices using the Expect-Regex engine
func (c *CiscoDriver) FetchConfig(dev *config.Device) ([]byte, error) {
	return FetchDeviceConfig(dev)
}
