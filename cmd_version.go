package main

import "fmt"

func printHelp() {
	fmt.Println("XConf Agent - Zero-Knowledge Network Backup CLI")
	fmt.Println("Usage:")
	fmt.Println("  xconf-agent <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  install    Install agent, register tenant token & agent key")
	fmt.Println("  uninstall  Unregister system service")
	fmt.Println("  start      Start the background system service")
	fmt.Println("  stop       Stop the background system service")
	fmt.Println("  restart    Restart the background system service")
	fmt.Println("  check      Perform local configuration and connectivity tests")
	fmt.Println("  decrypt    Offline restore command to decrypt configuration files")
	fmt.Println("  run        Run the backup scheduler daemon in the foreground")
	fmt.Println("  version    Display version and build information")
	fmt.Println("  help       Show this help manual")
	fmt.Println("\nUse 'xconf-agent <command> --help' for details on a specific command.")
}

func runVersion() {
	fmt.Println("XConf Agent v1.0.0 (Bootstrap Phase 1)")
	fmt.Println("License: Proprietary (All rights reserved)")
}
