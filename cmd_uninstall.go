package main

import (
	"flag"
	"fmt"

	"github.com/kardianos/service"

	"xconf-agent/config"
)

func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	configPath := fs.String("config", config.GetDefaultConfigPath(), "Path to config file")
	_ = fs.Parse(args)

	fmt.Println("Uninstalling XConf Agent service...")
	prg := &program{configPath: *configPath}
	s, err := service.New(prg, getServiceConfig(*configPath))
	if err != nil {
		fmt.Printf("Error: Failed to load service configurations: %v\n", err)
		return
	}
	_ = s.Stop()
	err = s.Uninstall()
	if err != nil {
		fmt.Printf("Warning: Could not remove system service: %v\n", err)
		fmt.Println("Hint: To unregister the system service, please run this command with administrative privileges.")
	} else {
		fmt.Println("Agent service successfully unregistered.")
	}
}
