package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"

	"xconf-agent/config"
)

func runInstall(args []string) {
	fmt.Println("Disclaimer: This software is provided 'as is' without warranty of any kind.")

	fs := flag.NewFlagSet("install", flag.ExitOnError)
	token := fs.String("token", "", "JWT token from xconf.ai dashboard")
	key := fs.String("key", "", "Hex-encoded AGENT_KEY")
	configPath := fs.String("config", config.GetDefaultConfigPath(), "Path to save config file")
	supabaseURL := fs.String("url", "", "Supabase API URL (optional, auto-detected from token)")

	_ = fs.Parse(args)

	// Check if config file already exists
	configExists := false
	if _, err := os.Stat(*configPath); err == nil {
		configExists = true
	}

	if *token == "" || *key == "" {
		if configExists {
			fmt.Printf("Existing configuration file found at %s. Performing service-only registration...\n", *configPath)
			cfg, err := config.LoadConfig(*configPath)
			if err != nil {
				fmt.Printf("Error: Existing config file is invalid: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[OK] Valid config loaded. Agent ID: %s, Tenant ID: %s\n", cfg.AgentID, cfg.TenantID)

			// Register system service
			prg := &program{configPath: *configPath}
			s, err := service.New(prg, getServiceConfig(*configPath))
			serviceExisted := false
			if err == nil {
				err = s.Install()
				if err != nil {
					if strings.Contains(strings.ToLower(err.Error()), "already exists") {
						serviceExisted = true
						fmt.Println("Info: The xconf-agent service is already registered on this system.")
					} else {
						fmt.Printf("Warning: Could not register system service: %v\n", err)
						fmt.Println("Hint: To register the agent as a system service, please run this command with administrative privileges (e.g., using sudo or Run as Administrator).")
						os.Exit(1)
					}
				} else {
					fmt.Println("Agent registered successfully as a system service.")
				}
			}
			fmt.Println()
			fmt.Println("======================================================")
			if serviceExisted {
				fmt.Println("XConf Agent service is ready!")
			} else {
				fmt.Println("XConf Agent service registered successfully!")
			}
			fmt.Println("To start the service, please run:")
			fmt.Println("   xconf-agent start")
			fmt.Println("======================================================")
			return
		}

		if *token == "" {
			fmt.Println("Error: --token is required for initial provisioning")
		}
		if *key == "" {
			fmt.Println("Error: --key is required for initial provisioning")
		}
		fs.Usage()
		os.Exit(1)
	}

	// 1. Verify key (Industry best practice + UX)
	_, err := config.ValidateKey(*key)
	if err != nil {
		fmt.Printf("Error: Invalid AGENT_KEY: %v\n", err)
		fmt.Println("Hint: The --key must be exactly 64 hexadecimal characters representing a 256-bit AES key.")
		os.Exit(1)
	}

	// 2. Resolve Supabase URL from token issuer hint
	urlVal := *supabaseURL
	if urlVal == "" {
		if iss, err := extractIssuerFromJWT(*token); err == nil && iss != "" {
			urlVal = strings.TrimSuffix(iss, "/auth/v1")
		}
	}
	if urlVal == "" {
		fmt.Println("Error: Supabase URL could not be auto-detected. Please specify --url explicitly.")
		os.Exit(1)
	}

	fmt.Println("Installing XConf Agent...")
	fmt.Printf("Supabase URL identified: %s\n", urlVal)
	fmt.Println("Verifying installation token with SaaS cloud server...")

	// 3. Contact the server to verify JWT and get the tenant_id
	verifyURL := fmt.Sprintf("%s/functions/v1/xconf-api/verify-install-token", strings.TrimSuffix(urlVal, "/"))
	req, err := http.NewRequest("POST", verifyURL, nil)
	if err != nil {
		fmt.Printf("Error: Failed to construct request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+*token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: Failed to verify token with server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: Token verification failed (HTTP %d): %s\n", resp.StatusCode, string(bodyBytes))
		os.Exit(1)
	}

	var verifyResp struct {
		TenantID        string `json:"tenant_id"`
		SupabaseURL     string `json:"supabase_url"`
		SupabaseAnonKey string `json:"supabase_anon_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		fmt.Printf("Error: Failed to decode server response: %v\n", err)
		os.Exit(1)
	}

	tenantID := verifyResp.TenantID
	fmt.Printf("[OK] Token verified. Tenant ID: %s\n", tenantID)

	// Build default config
	cfg := &config.Config{
		TenantID:        tenantID,
		AgentID:         generateUUID(),
		AgentKey:        *key,
		AgentJWT:        *token,
		SupabaseURL:     urlVal,
		SupabaseAnonKey: verifyResp.SupabaseAnonKey,
		Devices:         []config.Device{},
	}

	err = config.SaveConfig(*configPath, cfg)
	if err != nil {
		fmt.Printf("Error: Failed to save config to %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		absPath = *configPath
	}

	fmt.Printf("Config file successfully written to: %s (permissions: 0600)\n", absPath)
	
	// Register system service
	prg := &program{configPath: *configPath}
	s, err := service.New(prg, getServiceConfig(*configPath))
	if err == nil {
		err = s.Install()
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "already exists") {
				fmt.Println("Info: The xconf-agent service is already registered on this system.")
			} else {
				fmt.Printf("Warning: Could not register system service: %v\n", err)
				fmt.Println("Hint: To register the agent as a system service, please run this command with administrative privileges (e.g., using sudo or Run as Administrator).")
			}
		} else {
			fmt.Println("Agent registered successfully as a system service.")
		}
	}
	fmt.Println()
	fmt.Println("======================================================")
	fmt.Println("XConf Agent installed successfully!")
	fmt.Println()
	fmt.Println("To get started, please follow these steps:")
	fmt.Printf("1. Open the configuration file at the following path:\n   %s\n\n", absPath)
	fmt.Println("2. Add your network devices to the 'devices' list inside the file.")
	fmt.Println("3. Run the self-check command to verify connectivity and register your devices:")
	fmt.Println("   xconf-agent check")
	fmt.Println("======================================================")
}
