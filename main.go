package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "check":
		runCheck(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	case "run":
		runDaemon(os.Args[2:])
	case "start", "stop", "restart":
		runServiceControl(subcommand, os.Args[2:])
	case "version":
		runVersion()
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Printf("Error: Unknown command %q\n\n", subcommand)
		printHelp()
		os.Exit(1)
	}
}
