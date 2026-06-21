package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/crypto/ssh"

	"xconf-agent/config"
	"xconf-agent/driver"
	"xconf-agent/storage"
)

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", config.GetDefaultConfigPath(), "Path to config file")
	_ = fs.Parse(args)

	fmt.Println("Disclaimer: This software is provided 'as is' without warranty of any kind.")
	fmt.Println("======================================================")
	fmt.Println("  XConf Agent Self-Check Report")
	fmt.Println("======================================================")

	// 1. Check Config File
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("[FAIL] Config File Load: FAILED\n  └─ Error: %v\n", err)
		fmt.Println("======================================================")
		os.Exit(1)
	}
	fmt.Printf("[OK] Config File Load: SUCCESS (%d devices configured)\n", len(cfg.Devices))

	// 2. Check Key
	_, err = config.ValidateKey(cfg.AgentKey)
	if err != nil {
		fmt.Printf("[FAIL] Agent Key Check: INVALID\n  └─ Error: %v\n", err)
	} else {
		fmt.Println("[OK] Agent Key Check: VALID")
	}

	// 3. System Service Check
	isInstalled := false
	isRunning := false
	prg := &program{configPath: *configPath}
	s, err := service.New(prg, getServiceConfig(*configPath))
	if err != nil {
		fmt.Printf("[FAIL] OS Service Status: UNKNOWN\n  └─ Error: %v\n", err)
	} else {
		status, err := s.Status()
		if err != nil {
			if err == service.ErrNotInstalled {
				fmt.Println("[OK] OS Service Status: Uninstalled")
			} else {
				fmt.Printf("[FAIL] OS Service Status: PERMISSION DENIED (Run as Administrator to check status)\n  └─ Error: %v\n", err)
			}
		} else {
			isInstalled = true
			statusStr := "UNKNOWN"
			switch status {
			case service.StatusRunning:
				statusStr = "Running"
				isRunning = true
			case service.StatusStopped:
				statusStr = "Stopped"
			}
			fmt.Printf("[OK] OS Service Status: %s\n", statusStr)
		}
	}

	// 4. Cloud Connectivity Check
	sm := storage.NewStorageManager(cfg, *configPath)
	if _, err := sm.SendHeartbeat(); err != nil {
		fmt.Printf("[FAIL] Supabase Connection: FAILED\n  └─ Error: %v\n", err)
	} else {
		fmt.Println("[OK] Supabase Connection: SUCCESS (Heartbeat Verified)")
	}

	// 5. Device Reachability Check
	fmt.Println("\n--- Device Connectivity Check ---")
	if len(cfg.Devices) == 0 {
		absPath, err := filepath.Abs(*configPath)
		if err != nil {
			absPath = *configPath
		}
		fmt.Println("No devices configured in the configuration file.")
		fmt.Println()
		fmt.Println("How to resolve this:")
		fmt.Printf("1. Open the configuration file at the following path:\n   %s\n\n", absPath)
		fmt.Println("2. Add your network devices to the 'devices' list in the file.")
		fmt.Println("   Here is an example configuration format you can copy/paste:")
		fmt.Println("------------------------------------------------------")
		fmt.Println("agent_id: \"" + cfg.AgentID + "\"")
		fmt.Println("agent_key: \"" + cfg.AgentKey + "\"")
		fmt.Println("devices:")
		fmt.Println("  - name: \"Router-1\"")
		fmt.Println("    ip: \"192.168.1.1\"")
		fmt.Println("    protocol: \"ssh\" # or telnet")
		fmt.Println("    port: 22")
		fmt.Println("    username: \"admin\"")
		fmt.Println("    password: \"admin123\"")
		fmt.Println("    vendor: \"cisco\" # cisco, huawei, juniper, generic, etc.")
		fmt.Println("------------------------------------------------------")
		fmt.Println("3. After editing the file, run this command again:")
		fmt.Println("   xconf-agent check")
		fmt.Println("------------------------------------------------------")
	} else {
		for _, dev := range cfg.Devices {
			isTelnet := strings.ToLower(dev.Protocol) == "telnet"
			protocolName := "SSH"
			defaultPort := 22
			if isTelnet {
				protocolName = "Telnet"
				defaultPort = 23
			}

			port := dev.Port
			if port == 0 {
				port = defaultPort
			}
			addr := net.JoinHostPort(dev.IP, fmt.Sprintf("%d", port))
			fmt.Printf("[?] dev_%s (%s) %s: Checking %s...\n", dev.ID, dev.Name, addr, protocolName)
			
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				fmt.Printf("  [FAIL] TCP Connection failed to %s: %v\n", addr, err)
				continue
			}
			conn.Close()
			fmt.Println("  [OK] TCP Port open")

			drv, err := driver.GetDriver(dev.Vendor, dev.IP)
			if err != nil {
				fmt.Printf("  [FAIL] Driver loading failed: %v\n", err)
				continue
			}

			if _, isMock := drv.(*driver.MockDriver); isMock {
				fmt.Printf("  [OK] Mock Driver detected - Skipping real %s authentication\n", protocolName)
				continue
			}

			if isTelnet {
				_, err := drv.FetchConfig(&dev)
				if err != nil {
					fmt.Printf("  [FAIL] Telnet Auth/Collection Failed: %v\n", err)
				} else {
					fmt.Println("  [OK] Telnet Auth & Collection SUCCESS")
				}
			} else {
				password := dev.GetResolvedPassword()
				var callback ssh.HostKeyCallback
				var kexs, ciphers []string
				isLegacy := dev.LegacyCompatible != nil && *dev.LegacyCompatible
				if isLegacy {
					callback = ssh.InsecureIgnoreHostKey()
					kexs = driver.LegacyKeyExchanges
					ciphers = driver.LegacyCiphers
				} else {
					callback = driver.GetHostKeyCallback(&dev)
					kexs = driver.StrongKeyExchanges
					ciphers = driver.StrongCiphers
				}

				sshConfig := &ssh.ClientConfig{
					User: dev.Username,
					Auth: []ssh.AuthMethod{
						ssh.Password(password),
					},
					HostKeyCallback: callback,
					Timeout:         5 * time.Second,
					Config: ssh.Config{
						KeyExchanges: kexs,
						Ciphers:      ciphers,
					},
				}
				
				client, err := ssh.Dial("tcp", addr, sshConfig)
				if err != nil {
					fmt.Printf("  [FAIL] SSH Auth Failed: %v\n", err)
				} else {
					client.Close()
					if isLegacy {
						fmt.Println("  [OK] SSH Auth SUCCESS (Legacy Compatibility mode - Host Key skipped)")
					} else {
						fmt.Println("  [OK] SSH Auth SUCCESS (Host Key verification enforced - secure)")
					}
				}
			}
		}

		fmt.Println("\n------------------------------------------------------")
		
		// If some devices failed or no devices could be successfully verified, we can print warning.
		// For simplicity, we print Next Steps with service/foreground running actions.
		if isRunning {
			fmt.Println("[OK] OS service is ALREADY RUNNING in the background.")
			fmt.Println("    No action needed. Go back to the web console (https://xconf.ai) to view your backups!")
		} else {
			fmt.Println("Self-check complete. Next Steps to run XConf Agent:")
			fmt.Println()
			fmt.Println("[Option A: Temporary Debug Mode (Foreground)]")
			if runtime.GOOS == "windows" {
				fmt.Println("  Command: xconf-agent run")
			} else {
				fmt.Println("  Command: ./xconf-agent run")
			}
			fmt.Println("  [!] WARNING: This is for testing only. Backups will STOP if you close")
			fmt.Println("     this terminal window, log out, or restart your computer/server!")
			fmt.Println()
			
			if isInstalled {
				fmt.Println("[Option B: Permanent Auto-Recover Mode (Background Service)]")
				fmt.Println("  The background service is already registered. Start it now:")
				if runtime.GOOS == "windows" {
					fmt.Println("    xconf-agent start")
				} else {
					fmt.Println("    sudo ./xconf-agent start")
				}
			} else {
				fmt.Println("[Option B: Permanent Auto-Recover Mode (Background Service - RECOMMENDED)]")
				fmt.Println("  To ensure backups automatically recover and run after system reboots,")
				fmt.Println("  power outages, or user logouts, register as a system service:")
				fmt.Println()
				if runtime.GOOS == "windows" {
					fmt.Println("  1. Re-open CMD/PowerShell as Administrator")
					fmt.Println("  2. Register service: xconf-agent install")
					fmt.Println("  3. Start service:    xconf-agent start")
				} else if runtime.GOOS == "darwin" {
					fmt.Println("  1. Register service: sudo ./xconf-agent install")
					fmt.Println("  2. Start service:    sudo ./xconf-agent start")
				} else { // linux
					fmt.Println("  1. Register service: sudo ./xconf-agent install")
					fmt.Println("  2. Start service:    sudo ./xconf-agent start")
				}
			}
		}
		
		fmt.Println("------------------------------------------------------")
	}

	fmt.Println("======================================================")
}
