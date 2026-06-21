# XConf Edge Agent

A lightweight, self-contained network configuration backup daemon designed for zero-knowledge data privacy. The XConf Edge Agent pulls switch/router configurations over SSH, masks sensitive credentials locally, encrypts them at the source, and syncs them with Cloud Storage.

---

## 🔐 Core Philosophy & Security Design

XConf is built on the principle of **Zero-Knowledge Privacy**. Your network credentials and plaintext configuration data should never leave your local boundary:

*   **Edge-Side Masking**: Sensitive passwords, secret hashes, and SNMP community strings are stripped locally (`[MASKED]`) before transit.
*   **Source-Side Encryption**: Backups are encrypted locally using **AES-256-GCM** before uploading. Decryption keys are held strictly by you and processed locally in your browser sandbox.
*   **Decoupled Autonomy**: The agent runs as an independent local system daemon with its own built-in Cron scheduler and SQLite offline buffer queue, running resiliently even during SaaS connection outages.

---

## ⚡ Key Features

*   **Multi-Vendor Support**: Model-driven declaratively structured drivers for Cisco, Huawei, H3C, Ruijie, Fortinet, Juniper, and Aruba.
*   **Clean Diff Tracking**: Automatically strips temporal metadata (like timestamps or nvram write counts) so that Git comparisons only show functional configuration changes.
*   **Zero Sleep Overhead**: Uses a prompt-driven state-machine instead of arbitrary sleep delays, ensuring swift and complete configuration extraction.
*   **Cross-Platform**: Compiles into a single self-contained binary for Linux, macOS, and Windows.

---

## 🛠️ Build & Installation

### Prerequisites
*   Go 1.21 or higher

### Build from Source
```bash
# Clone the repository
git clone https://github.com/willdom-lee/xconf-agent.git
cd xconf-agent

# Build the binary
go build -o xconf-agent main.go
```

### Initial Provisioning
Refer to the instructions on the XConf Dashboard to fetch your tenant JWT token and security keys, then run:
```bash
./xconf-agent install --token="<YOUR_TOKEN>" --key="<YOUR_AGENT_KEY>"
./xconf-agent run
```

---

## 🤝 Tribute & Acknowledgments

This project draws heavy inspiration from the outstanding open-source project [Oxidized](https://github.com/ytti/oxidized) for its vendor configuration sanitizers and interactive session filters. We express our sincere respect and gratitude to the Oxidized community and its contributors.

---

## 💬 Feedback & Issues

For bugs, feature requests, or discussions regarding either the Edge Agent or the XConf platform, please feel free to open a [GitHub Issue](https://github.com/willdom-lee/xconf-agent/issues).
