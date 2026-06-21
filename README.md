# XConf Edge Agent

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

Welcome to the official repository for the **XConf Edge Agent** client.

The agent client code is currently undergoing final validation and polish. We will release the full Go source code here as soon as the final release builds are ready.

In the meantime, **this repository serves as our primary global feedback and community support hub.**

### 💬 Feedback & Feature Requests

We want to hear from you! Please feel free to open a [GitHub Issue](https://github.com/willdom-lee/xconf-agent/issues) or start a thread in [Discussions](https://github.com/willdom-lee/xconf-agent/discussions) to:

*   Request support for a specific network vendor (Cisco, Huawei, H3C, Fortinet, Juniper, Aruba, etc.)
*   Provide feedback on the XConf platform UI/UX or encryption design
*   Report bugs or request new features for the upcoming agent client release

### 🔐 Core Philosophy & Security Design

Once released, the Agent will execute XConf's core security philosophy:
*   **Zero-Knowledge Privacy**: Configurations are encrypted locally using AES-256-GCM before uploading. Decryption keys never touch the network or SaaS cloud.
*   **Edge-Side Masking**: Sensitive passwords, secret hashes, and SNMP community strings are stripped locally (`[MASKED]`) at the source.
*   **Decoupled Autonomy**: Runs as a self-contained local system daemon with its own built-in Cron scheduler and SQLite offline buffer queue.

---

<a name="中文"></a>
## 中文

欢迎来到 **XConf Edge Agent** 边缘客户端的官方仓库。

探针客户端的 Go 源码目前正在进行最终的安全验证与性能优化。我们将在发布版本准备就绪后，第一时间在此公开全部源代码。

在此期间，**本仓库将作为 XConf 项目主要的全球用户反馈与社区交流中心。**

### 💬 问题反馈与功能申请

我们非常期待听到您的声音！欢迎通过 [GitHub Issues](https://github.com/willdom-lee/xconf-agent/issues) 或 [Discussions](https://github.com/willdom-lee/xconf-agent/discussions) 讨论区随时反馈：

*   申请适配特定的网络厂商设备（如思科、华为、H3C、锐捷、飞塔、瞻博、Aruba 等）
*   对 XConf 网页端 UI/UX、交互体验或端到端加密机制的改进建议
*   在试用过程中遇到的 Bug 或对即将发布的 Agent 客户端的功能期望

### 🔐 核心安全架构设计

在正式开源发布后，Agent 将继续严格贯彻 XConf 的安全隐私底线：
*   **零知识数据盲化**：配置文件在边缘完成 AES-256-GCM 强加密后上传，解密主密钥仅保存在您的浏览器安全内存中，云端对明文完全盲视。
*   **边缘流式脱敏**：敏感账号密码、密文哈希、SNMP 团体名在离开您的本地网络前，即被自动脱敏遮蔽为 `[MASKED]`。
*   **解耦自治调度**：探针作为本地守护进程运行，拥有独立的定时器与离线 SQLite 缓冲队列，即便失去云端连接仍能继续按计划执行备份。
