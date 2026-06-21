package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"

	"xconf-agent/config"
	"xconf-agent/logger"
	"xconf-agent/storage"
)

type program struct {
	exit         chan struct{}
	configPath   string
	cron         *cron.Cron
	cronJobs     map[string]*cronJob // Keyed by device ID
	cronJobsLock sync.RWMutex
	cfgLock      sync.RWMutex
	cfg          *config.Config
	sem          chan struct{}
	wg           sync.WaitGroup
}

func (p *program) Start(s service.Service) error {
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	logger.Info("daemon", "", "Stopping XConf Agent service gracefully...")
	close(p.exit)
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		logger.Info("daemon", "", "All running backups completed.")
	case <-time.After(30 * time.Second):
		logger.Warn("daemon", "", "Timed out waiting for running backups to complete.")
	}
	logger.Info("daemon", "", "XConf Agent shut down.")
	return nil
}

func (p *program) run() {
	logger.Info("daemon", "", "XConf Agent background service started.")
	
	cfg, err := config.LoadConfig(p.configPath)
	if err != nil {
		logger.Fatal("daemon", "", "Failed to load config: %v", err)
		return
	}

	// Concurrency limiter (Max 5 backups)
	p.sem = make(chan struct{}, 5)

	p.cfgLock.Lock()
	p.cfg = cfg
	p.cfgLock.Unlock()

	// Print warnings for devices with legacy compatible mode enabled
	for _, dev := range cfg.Devices {
		if dev.LegacyCompatible != nil && *dev.LegacyCompatible {
			logger.Warn("ssh", dev.ID, "Legacy compatibility mode is enabled for %s (Host key verification disabled & legacy ciphers enabled). Connection is vulnerable to MITM attacks.", dev.Name)
		}
	}

	// Acquire single instance lock named after the config file path
	cleanup, err := config.AcquirePIDLock(p.configPath)
	if err != nil {
		logger.Fatal("daemon", "", "%v", err)
		os.Exit(1)
	}
	defer cleanup()

	sm := storage.NewStorageManager(cfg, p.configPath)

	// Initialize Cron scheduler
	p.cron = cron.New()

	p.cronJobsLock.Lock()
	p.cronJobs = make(map[string]*cronJob)

	// Register cron jobs for each device
	p.cfgLock.RLock()
	devices := p.cfg.Devices
	p.cfgLock.RUnlock()

	for _, dev := range devices {
		if dev.Schedule == "" {
			continue
		}
		d := dev
		entryID, err := p.cron.AddFunc(d.Schedule, func() {
			p.wg.Add(1)
			go func(d config.Device) {
				defer p.wg.Done()
				p.sem <- struct{}{}
				defer func() { <-p.sem }()
				executeDeviceBackup(sm, &d, "")
			}(d)
		})
		if err != nil {
			logger.Error("scheduler", d.ID, "Failed to register schedule %q: %v", d.Schedule, err)
		} else {
			p.cronJobs[d.ID] = &cronJob{
				EntryID:  entryID,
				Schedule: d.Schedule,
			}
			logger.Info("scheduler", d.ID, "Registered cron job: %s", d.Schedule)
		}
	}
	p.cronJobsLock.Unlock()

	p.cron.Start()
	defer p.cron.Stop()

	// Send initial heartbeat and handle cloud schedules
	hbResp, err := sm.SendHeartbeat()
	if err != nil {
		logger.Warn("api", "", "Failed to send initial heartbeat: %v", err)
	} else {
		logger.Info("api", "", "Initial heartbeat sent successfully.")
		if hbResp.Action == "shutdown" {
			logger.Warn("decommission", "", "Received decommission signal from cloud. Agent is shutting down gracefully...")
			decommissionSelf(p.configPath)
			return
		}
		p.handleCloudSchedules(sm, hbResp.Schedules)
	}

	// Start tickers for heartbeats, commands, and queue processing
	heartbeatTicker := time.NewTicker(1 * time.Minute)
	defer heartbeatTicker.Stop()

	commandTicker := time.NewTicker(15 * time.Second)
	defer commandTicker.Stop()

	queueTicker := time.NewTicker(5 * time.Minute)
	defer queueTicker.Stop()

	for {
		select {
		case <-p.exit:
			logger.Info("daemon", "", "Stopping XConf Agent service gracefully...")
			return
		case <-heartbeatTicker.C:
			hbResp, err := sm.SendHeartbeat()
			if err != nil {
				logger.Error("api", "", "Heartbeat ping failed: %v", err)
			} else {
				if hbResp.Action == "shutdown" {
					logger.Warn("decommission", "", "Received decommission signal from cloud. Agent is shutting down gracefully...")
					decommissionSelf(p.configPath)
					return
				}
				p.handleCloudSchedules(sm, hbResp.Schedules)
			}
		case <-commandTicker.C:
			p.cfgLock.RLock()
			currentAgentID := p.cfg.AgentID
			p.cfgLock.RUnlock()

			resp, err := sm.PollCommands(currentAgentID)
			if err != nil {
				continue
			}
			if resp != nil && resp.Command != nil {
				cmd := resp.Command
				logger.Info("daemon", cmd.Payload.DeviceID, "Received manual command: ID=%s, Type=%s", cmd.ID, cmd.CommandType)
				
				if cmd.CommandType == "BACKUP" {
					var targetDev *config.Device
					p.cfgLock.RLock()
					for _, dev := range p.cfg.Devices {
						if dev.ID == cmd.Payload.DeviceID {
							d := dev
							targetDev = &d
							break
						}
					}
					p.cfgLock.RUnlock()

					if targetDev != nil {
						p.wg.Add(1)
						go func(d config.Device, cmdID string) {
							defer p.wg.Done()
							p.sem <- struct{}{}
							defer func() { <-p.sem }()
							executeDeviceBackup(sm, &d, cmdID)
						}(*targetDev, cmd.ID)
					} else {
						errMsg := fmt.Sprintf("Device %s requested in manual backup is not configured locally in agent's config.yaml", cmd.Payload.DeviceID)
						logger.Error("daemon", cmd.Payload.DeviceID, "%s", errMsg)
						_ = sm.ReportFailure(cmd.Payload.DeviceID, cmd.ID, errMsg)
					}
				}
			}
		case <-queueTicker.C:
			sm.ProcessQueue()
		}
	}
}

func (p *program) handleCloudSchedules(sm *storage.StorageManager, schedules []storage.DeviceSchedule) {
	cfg, err := config.LoadConfig(p.configPath)
	if err != nil {
		logger.Error("daemon", "", "Failed to reload config during schedule sync: %v", err)
		return
	}

	p.cfgLock.Lock()
	p.cfg = cfg
	p.cfgLock.Unlock()

	sm.UpdateConfig(cfg)

	p.cronJobsLock.Lock()
	defer p.cronJobsLock.Unlock()

	for _, s := range schedules {
		// Find the local device configuration
		var dev config.Device
		found := false
		for _, d := range cfg.Devices {
			if d.ID == s.ID {
				dev = d
				found = true
				break
			}
		}

		if !found {
			// This device is configured on cloud but not locally in config.yaml
			continue
		}

		// Determine target schedule (Cloud schedule overrides local schedule)
		targetSchedule := dev.Schedule // Default to local schedule
		if s.BackupSchedule != nil {
			targetSchedule = *s.BackupSchedule
		}

		// Check if we already have a job running for this device
		job, exists := p.cronJobs[s.ID]
		if exists {
			// If the schedule hasn't changed, do nothing
			if job.Schedule == targetSchedule {
				continue
			}

			// Schedule changed! Remove the old job
			p.cron.Remove(job.EntryID)
			delete(p.cronJobs, s.ID)
			logger.Info("scheduler", s.ID, "Removed outdated schedule task.")
		}

		// If the target schedule is empty (Manual backup only), do not register a cron job
		if targetSchedule == "" {
			logger.Info("scheduler", s.ID, "Configured to manual backup only.")
			continue
		}

		// Register the new cron job
		d := dev // Capture for goroutine
		entryID, err := p.cron.AddFunc(targetSchedule, func() {
			p.wg.Add(1)
			go func(d config.Device) {
				defer p.wg.Done()
				p.sem <- struct{}{}
				defer func() { <-p.sem }()
				executeDeviceBackup(sm, &d, "")
			}(d)
		})
		if err != nil {
			logger.Error("scheduler", s.ID, "Failed to register schedule %q: %v", targetSchedule, err)
		} else {
			p.cronJobs[s.ID] = &cronJob{
				EntryID:  entryID,
				Schedule: targetSchedule,
			}
			logger.Info("scheduler", s.ID, "Successfully registered schedule: %q", targetSchedule)
		}
	}

	// Prune cron tasks of deleted devices
	cloudIds := make(map[string]bool)
	for _, s := range schedules {
		cloudIds[s.ID] = true
	}

	for devID, job := range p.cronJobs {
		if !cloudIds[devID] {
			p.cron.Remove(job.EntryID)
			delete(p.cronJobs, devID)
			logger.Info("scheduler", devID, "Removed deleted device's schedule task.")
		}
	}
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", config.GetDefaultConfigPath(), "Path to config file")
	_ = fs.Parse(args)

	fmt.Printf("Starting XConf Agent daemon (config: %s)...\n", *configPath)
	fmt.Println("========================================================================")
	fmt.Println("[WARNING: TEMPORARY FOREGROUND RUN]")
	fmt.Println("- This agent is running in foreground interactive mode.")
	fmt.Println("- Closing this terminal window or restarting this machine will STOP backups!")
	fmt.Println("- To ensure permanent backup daemon running and auto-recovery on boot:")
	if runtime.GOOS == "windows" {
		fmt.Println("  Please stop this process (Ctrl+C) and run 'xconf-agent install'")
		fmt.Println("  using Administrator privileges to register as a Windows system service.")
	} else if runtime.GOOS == "darwin" {
		fmt.Println("  Please stop this process (Ctrl+C) and run 'sudo ./xconf-agent install'")
		fmt.Println("  to register as a macOS launchd service.")
	} else { // linux
		fmt.Println("  Please stop this process (Ctrl+C) and run 'sudo ./xconf-agent install'")
		fmt.Println("  to register as a Linux systemd service.")
	}
	fmt.Println("========================================================================")

	prg := &program{
		configPath: *configPath,
	}

	s, err := service.New(prg, getServiceConfig(*configPath))
	if err != nil {
		fmt.Printf("Error initializing service: %v\n", err)
		os.Exit(1)
	}

	if err := s.Run(); err != nil {
		logger.Error("daemon", "", "Daemon runner failed: %v", err)
		os.Exit(1)
	}
}

func getServiceConfig(configPath string) *service.Config {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		absPath = configPath
	}
	return &service.Config{
		Name:        "xconf-agent",
		DisplayName: "XConf Agent Service",
		Description: "Zero-Knowledge Network Configuration Backup Agent",
		Arguments:   []string{"run", "--config", absPath},
	}
}

func runServiceControl(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	configPath := fs.String("config", config.GetDefaultConfigPath(), "Path to config file")
	_ = fs.Parse(args)

	prg := &program{configPath: *configPath}
	s, err := service.New(prg, getServiceConfig(*configPath))
	if err != nil {
		fmt.Printf("Error initializing service control: %v\n", err)
		os.Exit(1)
	}

	var opErr error
	switch action {
	case "start":
		opErr = s.Start()
	case "stop":
		opErr = s.Stop()
	case "restart":
		opErr = opErr // placeholder
		opErr = s.Restart()
	}

	if opErr != nil {
		fmt.Printf("Error: Failed to %s service: %v\n", action, opErr)
		fmt.Println("Hint: Try running this command with administrative privileges (e.g., Run CMD as Administrator or use sudo).")
		os.Exit(1)
	}

	if action == "start" {
		fmt.Println("Successfully sent start signal to the background service.")
		fmt.Println()
		fmt.Println("[OK] XConf Agent is now running in the background as a system service.")
		if runtime.GOOS == "windows" {
			fmt.Println("[OK] The service is configured to start automatically on Windows boot.")
		} else if runtime.GOOS == "darwin" {
			fmt.Println("[OK] The service is managed by macOS launchd and will start automatically.")
		} else { // linux
			fmt.Println("[OK] The service is enabled in systemd and will auto-start on Linux boot.")
		}
		fmt.Println("    It will safely survive and recover from system reboots or power outages.")
	} else {
		fmt.Printf("Successfully sent %s signal to the background service.\n", action)
	}
}

func decommissionSelf(configPath string) {
	logger.Warn("decommission", "", "Starting local decommission and self-destruction process...")

	// 1. Uninstall system service
	prg := &program{configPath: configPath}
	s, err := service.New(prg, getServiceConfig(configPath))
	if err == nil {
		_ = s.Stop()
		errUninstall := s.Uninstall()
		if errUninstall != nil {
			logger.Warn("decommission", "", "Failed to uninstall agent from system services: %v", errUninstall)
		} else {
			logger.Info("decommission", "", "Successfully uninstalled from system services.")
		}
	} else {
		logger.Warn("decommission", "", "Failed to load service configuration: %v", err)
	}

	// 2. Clear credentials in config.yaml
	cleanLocalConfig(configPath)
}

func cleanLocalConfig(configPath string) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		logger.Error("decommission", "", "Failed to read configuration file: %v", err)
		return
	}

	var cfgMap map[string]interface{}
	err = yaml.Unmarshal(data, &cfgMap)
	if err != nil {
		logger.Error("decommission", "", "Failed to parse configuration file: %v", err)
		return
	}

	// Wipe credentials but keep devices metadata
	cfgMap["agent_key"] = ""
	cfgMap["agent_jwt"] = ""

	updatedData, err := yaml.Marshal(&cfgMap)
	if err != nil {
		logger.Error("decommission", "", "Failed to serialize configuration file: %v", err)
		return
	}

	decomPath := configPath + ".decommissioned"
	err = ioutil.WriteFile(decomPath, updatedData, 0600)
	if err != nil {
		logger.Error("decommission", "", "Failed to write decommissioned configuration file: %v", err)
		return
	}

	logger.Info("decommission", "", "Successfully cleared agent_key and agent_jwt. Configuration file has been renamed and disabled at: %s", decomPath)

	err = os.Remove(configPath)
	if err != nil {
		logger.Warn("decommission", "", "Failed to delete original configuration file: %v", err)
	} else {
		logger.Info("decommission", "", "Successfully deleted original configuration file: %s", configPath)
	}
}
