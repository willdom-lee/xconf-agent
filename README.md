# XConf Edge Agent

A lightweight, self-contained network configuration backup daemon designed for zero-knowledge data privacy. The XConf Edge Agent pulls switch/router configurations over SSH/Telnet, masks sensitive credentials locally, encrypts them at the source, and syncs them with Cloud Storage.

一款轻量级、自包含的网络设备配置备份守护进程，专为“零知识”数据隐私安全设计。XConf Edge Agent 通过 SSH/Telnet 协议抓取交换机/路由器配置，在本地自动脱敏敏感凭证，并在源端完成 AES-256 加密，最终同步至云端存储。

---

* [English Documentation](#english-documentation)
* [中文文档](#中文文档)

---

<a name="english-documentation"></a>
## English Documentation

### 🔐 Core Philosophy & Security Design

XConf is built on the principle of **Zero-Knowledge Privacy**. Your network credentials and plaintext configuration data should never leave your local boundary:

*   **Edge-Side Masking**: Sensitive passwords, secret hashes, and SNMP community strings are stripped locally (`[MASKED]`) before transit.
*   **Source-Side Encryption**: Backups are encrypted locally using **AES-256-GCM** before uploading. Decryption keys are held strictly by you and processed locally in your browser sandbox.
*   **Decoupled Autonomy**: The agent runs as an independent local system daemon with its own built-in Cron scheduler and SQLite offline buffer queue, running resiliently even during SaaS connection outages.

### ⚡ Key Features

*   **Multi-Vendor Support**: Model-driven declaratively structured drivers for Cisco, Huawei, H3C, Ruijie, Fortinet, Juniper, and Aruba.
*   **Clean Diff Tracking**: Automatically strips temporal metadata (like timestamps or nvram write counts) so that Git comparisons only show functional configuration changes.
*   **Zero Sleep Overhead**: Uses a prompt-driven state-machine instead of arbitrary sleep delays, ensuring swift and complete configuration extraction.
*   **Cross-Platform**: Compiles into a single self-contained binary for Linux, macOS, and Windows.

### 🛠️ Build & Installation

#### Prerequisites
*   Go 1.21 or higher

#### Build from Source
```bash
# Clone the repository
git clone https://github.com/willdom-lee/xconf-agent.git
cd xconf-agent

# Build the binary
go build -o xconf-agent main.go
```

#### Initial Provisioning
Refer to the instructions on the XConf Dashboard to fetch your tenant JWT token and security keys, then run:
```bash
./xconf-agent install --token="<YOUR_TOKEN>" --key="<YOUR_AGENT_KEY>"
./xconf-agent run
```

### 🤝 Tribute & Acknowledgments

This project draws heavy inspiration from the outstanding open-source project [Oxidized](https://github.com/ytti/oxidized) for its vendor configuration sanitizers and interactive session filters. We express our sincere respect and gratitude to the Oxidized community and its contributors.

### 💬 Feedback & Issues

For bugs, feature requests, or discussions regarding either the Edge Agent or the XConf platform, please feel free to open a [GitHub Issue](https://github.com/willdom-lee/xconf-agent/issues).

---

<a name="中文文档"></a>
## 中文文档

### 🔐 核心安全架构设计

XConf 的基石是**“零知识”隐私保护原则**。您的网络设备管理凭证及配置明文永远不会离开您的本地网络边界：

*   **边缘本地脱敏**：敏感账号密码、密文哈希、SNMP 团体名在离开本地前，即被探针流式自动脱敏遮蔽为 `[MASKED]`。
*   **源端本地加密**：配置文件在边缘完成 **AES-256-GCM** 强加密后上传，解密主密钥仅保存在您的本地浏览器安全内存中，云端对您的明文完全盲视。
*   **解耦自治调度**：探针作为本地守护进程运行，拥有独立的内置 Cron 定时器与离线 SQLite 缓冲队列，即便失去云端连接仍能继续按计划执行备份。

### ⚡ 核心功能特性

*   **多厂商适配**：基于声明式声明模型的驱动设计，原生支持思科 (Cisco)、华为 (Huawei)、华三 (H3C)、锐捷 (Ruijie)、飞塔 (Fortinet)、瞻博 (Juniper) 以及 Aruba 等设备。
*   **干净的版本对比**：自动过滤配置中的非功能性文本（如保存时间戳、NVRAM 写入次数），确保 Git 版本对比只呈现纯粹的配置差异。
*   **零等待会话引擎**：基于 Expect 正则状态机驱动交互，无需设置任意硬等待延时（`sleep`），实现极速且完整的配置流提取。
*   **跨平台分发**：支持一键编译为 Linux、macOS 以及 Windows 的单体绿色无依赖二进制。

### 🛠️ 编译与安装

#### 前置要求
*   Go 1.21 或更高版本

#### 源码编译
```bash
# 克隆仓库
git clone https://github.com/willdom-lee/xconf-agent.git
cd xconf-agent

# 编译生成可执行文件
go build -o xconf-agent main.go
```

#### 初始化注册与启动
参考 XConf 控制台（Dashboard）中的引导页拷贝您的租户 JWT 令牌与 AES 秘钥，执行以下命令：
```bash
./xconf-agent install --token="<您的 Token>" --key="<您的 AES 秘钥>"
./xconf-agent run
```

### 🤝 致谢与开源致敬

本项目在网络设备厂商配置过滤器与会话交互机制的设计上，深度参考并致敬了优秀的开源项目 [Oxidized](https://github.com/ytti/oxidized)。在此对 Oxidized 社区及其全体贡献者表示诚挚的敬意与感谢。

### 💬 问题反馈与交流

如果您在试用过程中遇到任何 Bug、有新厂商适配申请、或对 XConf 架构有任何建议，欢迎随时提交 [GitHub Issue](https://github.com/willdom-lee/xconf-agent/issues)。

