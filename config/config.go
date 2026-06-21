package config

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"xconf-agent/logger"
)

// ConfigDir holds the directory path containing the loaded config file.
var ConfigDir string


// Device describes a target network device configuration
type Device struct {
	ID                    string `yaml:"id"`
	Name                  string `yaml:"name"`
	IP                    string `yaml:"ip"`
	Port                  int    `yaml:"port"`
	Protocol              string `yaml:"protocol"` // ssh | telnet (default to ssh if empty)
	Vendor                string `yaml:"vendor"`   // h3c | cisco
	Username              string `yaml:"username"`
	Password              string `yaml:"password"` // can be env:VAR_NAME or literal
	Schedule              string `yaml:"schedule"` // cron expression
	LegacyCompatible      *bool  `yaml:"legacy_compatible"`
}

// Config maps the YAML configuration file structure
type Config struct {
	TenantID        string   `yaml:"tenant_id"`
	AgentID         string   `yaml:"agent_id"`
	AgentKey        string   `yaml:"agent_key"` // hex-encoded
	AgentJWT        string   `yaml:"agent_jwt"`
	SupabaseURL     string   `yaml:"supabase_url"`
	SupabaseAnonKey string   `yaml:"supabase_anon_key"`
	Devices         []Device `yaml:"devices"`
}

// GetResolvedPassword returns the real password, resolving env variables if prefixed with "env:"
func (d *Device) GetResolvedPassword() string {
	if strings.HasPrefix(d.Password, "env:") {
		envVar := strings.TrimPrefix(d.Password, "env:")
		val := os.Getenv(envVar)
		if val == "" {
			fmt.Fprintf(os.Stderr, "WARNING: Environment variable %q is not set, using empty password\n", envVar)
		}
		return val
	}
	return d.Password
}

// ValidateKey checks if the hexKey is a valid 64-character hexadecimal representation of a 32-byte key
func ValidateKey(hexKey string) ([]byte, error) {
	hexKey = strings.TrimSpace(hexKey)
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("cryptographic key length must be exactly 64 hexadecimal characters (256-bit), got %d characters", len(hexKey))
	}
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("cryptographic key must be a valid hexadecimal string: %w", err)
	}
	return decoded, nil
}

func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}
	if uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return false
	}
	return true
}

func generateDeterministicUUID(agentID, key string) string {
	hasher := md5.New()
	hasher.Write([]byte(agentID + ":" + key))
	hash := hasher.Sum(nil)

	// Set version to 4
	hash[6] = (hash[6] & 0x0f) | 0x40
	// Set variant to RFC 4122
	hash[8] = (hash[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:])
}

// LoadConfig loads the configuration file from path, enforces permissions checks, and validates the configuration
func LoadConfig(path string) (*Config, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to locate config file: %w", err)
	}

	absPath, err := filepath.Abs(path)
	if err == nil {
		ConfigDir = filepath.Dir(absPath)
		logger.SetDataDir(ConfigDir)
	} else {
		ConfigDir = filepath.Dir(path)
		logger.SetDataDir(ConfigDir)
	}

	// Force file permissions to be owner-only (0600 on Unix, custom DACL on Windows)
	_ = HardenConfigPermissions(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Validation of key format (industry best practice)
	if cfg.AgentKey != "" {
		if _, err := ValidateKey(cfg.AgentKey); err != nil {
			return nil, fmt.Errorf("config error: invalid agent_key: %w", err)
		}
	}

	seenIDs := make(map[string]bool)
	for i, dev := range cfg.Devices {
		// Automatically generate a deterministic UUID if ID is missing or invalid
		if dev.ID == "" || !isValidUUID(dev.ID) {
			sourceKey := dev.ID
			if sourceKey == "" {
				sourceKey = dev.Name
			}
			cfg.Devices[i].ID = generateDeterministicUUID(cfg.AgentID, sourceKey)
		}

		id := cfg.Devices[i].ID
		if seenIDs[id] {
			return nil, fmt.Errorf("duplicate device ID/name %q found in config", id)
		}
		seenIDs[id] = true
		if dev.IP == "" {
			return nil, fmt.Errorf("config error: device %s is missing IP address", id)
		}
		if dev.Username == "" {
			return nil, fmt.Errorf("device %q missing required field: username", id)
		}
		v := strings.ToLower(dev.Vendor)
		if v != "h3c" && v != "cisco" && v != "huawei" && v != "ruijie" && v != "fortinet" && v != "juniper" && v != "aruba" && v != "mock" {
			return nil, fmt.Errorf("config error: device %s has unsupported vendor %q. Supported vendors are: cisco, huawei, h3c, ruijie, fortinet, juniper, aruba, mock", id, dev.Vendor)
		}
		proto := strings.ToLower(dev.Protocol)
		if proto != "" && proto != "ssh" && proto != "telnet" {
			return nil, fmt.Errorf("config error: device %s has unsupported protocol %q (must be 'ssh' or 'telnet')", id, dev.Protocol)
		}
	}

	return &cfg, nil
}

// SaveConfig writes the configuration to path, enforcing 0600 permissions
func SaveConfig(path string, cfg *Config) error {
	var data []byte
	var err error

	if len(cfg.Devices) == 0 {
		template := `# ==============================================================================
# XConf Agent 配置文件 (XConf Agent Configuration)
# 安全提示：此文件包含敏感的加密密钥及云端访问令牌，文件权限必须设置为 0600 (仅所有者可读写)
#
# 目录与数据收拢说明 (Folder Sandbox Description)：
#   本探针采用“绿色沙箱目录”设计，当本配置文件保存在某个文件夹内时：
#   1. 运行日志会自动生成在同级的 data/agent.log 中。 (Logs are written to relative data/agent.log)
#   2. 本地加密备份包会安全地收拢在同级的 data/history/ 目录下。 (Backups are stored under data/history/)
#   3. 常用命令、排错与灾难解密指南请参考同级目录下的 README.txt (英文) 或 README_zh.txt (中文)。
#      (Please refer to README.txt (English) or README_zh.txt (Chinese) in the same directory)
# ==============================================================================

tenant_id: "%s"  # 您的租户组织唯一标识 (由系统自动解析)
agent_id: "%s"   # 当前探针节点的唯一标识 (安装时自动生成)
agent_key: "%s" # 本地 AES-256-GCM 强加密密钥 (请线下妥善保管)
agent_jwt: "%s" # 用于与云端 API 安全通信的 JWT 令牌 (自动轮询认证)
supabase_url: "%s" # 云端 API 服务网关终结点
supabase_anon_key: "%s" # Supabase 匿名公钥

# ==============================================================================
# 网络设备纳管列表 (Network Devices List)
# 运维指引：
#   1. 新增设备：直接在 devices 列表中添加新项，填入 IP、用户名、密码等参数。
#   2. 安全秘钥：系统通过 agent_id + 唯一的设备名称 (name) 自动进行云端安全映射，
#      因此您完全不需要手动管理复杂的设备 UUID，只需保证设备名称 (name) 唯一即可。
#   3. 密码安全：password 字段支持明文密码，也支持从环境变量动态读取 (格式为 env:环境变量名)。
#   4. SSH 校验与算法兼容性 (SSH Verification & Legacy Compatibility)：
#      默认情况下，探针对 SSH 设备启用严格主机密钥校验 (TOFU 模式)。
#      若设备较为老旧且使用已被现代标准废弃的加密算法 (如 diffie-hellman-group1-sha1 等)，
#      请显式配置：legacy_compatible: true。此配置将自动跳过主机校验并自动放行老旧弱密码算法。
# ==============================================================================
devices:
  - name: "Switch-Core-1"                  # 可视化设备唯一名称 (请保证同一探针下唯一)
    ip: "192.168.1.1"                      # 设备的管理 IP 地址 (根据您的真实网络修改)
    port: 22                               # 访问端口 (SSH 默认 22，Telnet 默认 23)
    protocol: "ssh"                        # 通信协议 ("ssh" 或 "telnet")
    vendor: "cisco"                        # 设备厂商类型 ("cisco", "huawei", "h3c", "ruijie", "fortinet", "juniper", "aruba")
    username: "admin"                      # 登录用户名
    password: "your_password_here"         # 登录密码 (支持明文或 env:VAR)
    # legacy_compatible: true              # 兼容模式：放宽安全限制以支持老旧弱密钥/弱算法 (默认为 false)

`
		data = []byte(fmt.Sprintf(template, cfg.TenantID, cfg.AgentID, cfg.AgentKey, cfg.AgentJWT, cfg.SupabaseURL, cfg.SupabaseAnonKey))
	} else {
		data, err = yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML config: %w", err)
		}
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write file with 0600 permissions
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Harden permissions (especially for Windows support)
	if err := HardenConfigPermissions(path); err != nil {
		return fmt.Errorf("failed to harden config file permissions: %w", err)
	}

	absPath, err := filepath.Abs(path)
	if err == nil {
		ConfigDir = filepath.Dir(absPath)
		logger.SetDataDir(ConfigDir)
	} else {
		ConfigDir = filepath.Dir(path)
		logger.SetDataDir(ConfigDir)
	}

	// Generate README files
	_ = SaveReadme(path)

	return nil
}

// SaveReadme generates README.txt and README_en.txt in the same directory as the config path.
func SaveReadme(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	zhContent := `==============================================================================
    XConf Agent 首次使用向导与运维、排错、灾难恢复快速参考手册 (中文版)
==============================================================================

本探针已成功安装在当前目录。所有运行数据、日志和本地加密备份均收拢在本目录下。

------------------------------------------------------------------------------
0. 首次使用起步向导
------------------------------------------------------------------------------
若您是首次在此电脑上配置并启动探针，请依次执行以下 4 步：

第一步：配置您的网络设备 (Configure Devices)
  用文本编辑器打开本目录下的 config.yaml 文件，找到末尾的 "devices" 列表。
  根据其中的注释示例，填入您需要备份的交换机、路由器的 IP 地址、用户名、密码等参数。

第二步：执行本地连线自检 (Run Connectivity Check)
  在当前目录下打开命令行终端（CMD 或 PowerShell），执行以下自检命令：
    xconf-agent check
  确认控制台输出的所有设备连接状态均为 [OK] SUCCESS。如果有报错，请参考第 3 节进行排错。

第三步：将探针挂载为后台自动运行服务 (Install & Start Service)
  为了在服务器关机重启、断电后系统能自动恢复备份服务，请以管理员身份运行 CMD，
  进入当前目录下，依次执行以下命令安装并启动服务：
    xconf-agent install
    xconf-agent start
  一旦成功，服务便会常驻 Windows 后台并随系统开机自启。

第四步：前往 SaaS 云端控制台验证 (Verify on Cloud)
  登录 xconf.ai 控制台，确认此探针状态显示为“在线”。您可以尝试手动下发一次备份，
  并前往备份历史中查看本地加密上传的配置文件。

------------------------------------------------------------------------------
1. 常用运维管理命令 (Common Commands)
------------------------------------------------------------------------------
* 本地自检：xconf-agent check
  (检测配置文件正确性、Supabase 连接以及设备 SSH/Telnet 可达性)
* 前台调试启动：xconf-agent run
  (在前台交互模式运行，方便实时查看命令输出与备份过程)
* 后台系统服务控制 (需以管理员权限运行 CMD/PowerShell)：
  - 启动服务：xconf-agent start
  - 停止服务：xconf-agent stop
  - 重启服务：xconf-agent restart
  - 卸载服务：xconf-agent uninstall

------------------------------------------------------------------------------
2. 本地灾难解密与恢复指引 (Local Decryption & Recovery)
------------------------------------------------------------------------------
当云端控制台不可用时，您可以使用本地探针自带的解密工具，脱机解密本地的配置文件。

[!] 极重要前提：在运行以下解密命令前，请确保您的命令行终端已经切换到了当前探针所在的文件夹目录下！

具体脱机解密操作步骤（小白指引）：
  步骤一：打开命令行终端（CMD 或 PowerShell）。
  步骤二：使用 "cd" 命令切换到您的探针安装路径。
         例如您的探针装在 D:\xconf-agent，则需输入：cd /d D:\xconf-agent
         例如您的探针装在 C:\Users\Username\xconf-agent，则需输入：cd C:\Users\Username\xconf-agent
  步骤三：运行解密恢复命令：
         xconf-agent decrypt --file=[加密文件相对路径] --key=[您的AGENT_KEY] --out=[输出的明文文件路径]

         例如（直接复制并修改密钥即可）：
         xconf-agent decrypt --file=data\history\dev_xxxx\dev_xxxx_20260619.raw.enc --key=您的64位HEX密钥 --out=restore_config.txt

  步骤四：解密成功后，您可直接用文本编辑器打开当前目录下生成的 "restore_config.txt" 查看设备配置明文。

------------------------------------------------------------------------------
3. 日志查看与快速排错 (Troubleshooting)
------------------------------------------------------------------------------
* 本地文件日志：直接查看同目录下的 data\agent.log 文件。
* 操作系统日志：
  - Windows: 运行 eventvwr.msc，在“Windows 日志 -> 应用程序”中筛选事件源“xconf-agent”。
  - Linux: 运行 journalctl -u xconf-agent.service -f
* 常见错误排查：
  - [Permission Denied]：Windows 下请右键选择“以管理员身份运行”打开 CMD 再执行 install/start 等指令。
  - [Host key verification failed]：SSH 主机密钥校验失败。默认情况下开启严格的主机校验。若连接老旧设备，可在 config.yaml 中对该设备配置 legacy_compatible: true 以跳过主机校验并开启弱加密算法兼容支持。
* 杀毒软件与终端安全防护 (EDR) 拦截：
  - 探针在安装为后台系统服务并设置开机自启时，可能触发 Windows Defender、卡巴斯基 (Kaspersky)、Bitdefender、360、火绒等终端安全与防护软件的警报。请在安装时选择“允许本次操作”，或将探针程序及其所在目录加入到安全排除白名单中，以保障服务的正常后台常驻。
* 网络防火墙与态势感知报备：
  - 探针需要主动发起对网络资产管理端口（22/SSH 或 23/Telnet）的连接。若局域网内部署了网络准入、IDS/NDR 流量检测或态势感知平台，请对探针 IP 进行内部接入报备，并在安全防火墙中实施单向的定向访问策略放行，以规避误报内网扫描或横向渗透警报。
==============================================================================`

	enContent := `==============================================================================
  XConf Agent Onboarding, Troubleshooting & Disaster Decryption Manual (EN)
==============================================================================

This agent is installed in this directory. Running logs and local encrypted backups are stored here.

------------------------------------------------------------------------------
0. First-Time Onboarding Guide
------------------------------------------------------------------------------
Follow these 4 steps to get started:

Step 1: Configure Your Devices
  Open the config.yaml file in this directory and find the "devices" list at the bottom.
  Enter your switches/routers' IP, username, and password using the provided template.

Step 2: Run Connection Self-Check
  Open your terminal (CMD or PowerShell) in this directory and execute:
    xconf-agent check
  Verify that all device connection checks display [OK] SUCCESS.

Step 3: Install & Start Service (Background Service)
  To ensure backups recover from reboots/outages, open CMD as Administrator,
  navigate to this folder, and run:
    xconf-agent install
    xconf-agent start
  The daemon service will now run in the background and start automatically on boot.

Step 4: Verify on SaaS Cloud Console
  Log in to the xconf.ai dashboard, verify that the agent is "Online", and trigger a manual backup.

------------------------------------------------------------------------------
1. Common O&M Commands
------------------------------------------------------------------------------
* Self-Check: xconf-agent check
* Temporary Debug Run (Foreground): xconf-agent run
* Service Management (Administrator privileges required):
  - Start service:   xconf-agent start
  - Stop service:    xconf-agent stop
  - Restart service: xconf-agent restart
  - Uninstall:       xconf-agent uninstall

------------------------------------------------------------------------------
2. Local Disaster Decryption & Recovery
------------------------------------------------------------------------------
If the cloud dashboard is unavailable, decrypt local backup snapshots offline:

[!] WARNING: Always change directory (cd) to this agent folder in your terminal before running!

1. Open terminal (CMD or PowerShell).
2. Change directory:
   e.g. cd /d D:\xconf-agent
3. Run decryption:
   xconf-agent decrypt --file=[relative_path] --key=[AGENT_KEY] --out=[output_path]
   e.g.
   xconf-agent decrypt --file=data\history\dev_xxxx\dev_xxxx.raw.enc --key=your_hex_key --out=restore.txt

------------------------------------------------------------------------------
3. Logging & Troubleshooting
------------------------------------------------------------------------------
* Local Log File: Check data\agent.log in this directory.
* System Events:
  - Windows: Open Event Viewer (eventvwr.msc) -> Windows Logs -> Application -> Filter Source: xconf-agent.
  - Linux: Run journalctl -u xconf-agent.service -f
* Antivirus & EDR Whitelisting:
  - Installing or starting the agent background service may trigger warning alerts from mainstream antivirus software (e.g., Windows Defender, Bitdefender, Norton, McAfee) or enterprise EDR platforms (e.g., CrowdStrike, SentinelOne). Please select "Allow this action" or manually add the agent executable and its directory to your antivirus exclusion whitelist to allow daemon autostart.
* Firewall & IDS/NDR Security Compliance:
  - The agent automatically connects to configured devices over port 22 (SSH) or port 23 (Telnet). If your corporate network utilizes intrusion detection (IDS/IPS), network detection and response (NDR), or SIEM auditing, please register the agent's host IP in advance and configure firewall rules to only permit outbound connections to specified devices to avoid security incident alerts.
==============================================================================`

	enPath := filepath.Join(dir, "README.txt")
	zhPath := filepath.Join(dir, "README_zh.txt")

	if err := os.WriteFile(enPath, []byte(enContent), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(zhPath, []byte(zhContent), 0644); err != nil {
		return err
	}
	return nil
}

