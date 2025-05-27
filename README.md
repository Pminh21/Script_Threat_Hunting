# 🔍 CyberVenator Suite Tool

> **Advanced Windows Forensics & Incident Response Toolkit**

A comprehensive security analysis tool designed for digital forensics, incident response, and threat hunting on Windows systems.

---

## 🛡️ **Core Modules**

### 🧬 **1. Process Injection Detection**
**🔧 Engine:** HollowsHunter (x64/x86)
- 🎯 **Purpose:** Detect code injection, process hollowing, and memory manipulation
- 📁 **Output:** `hollows_hunter/` → CSV reports & memory dumps

### 🖥️ **2. System Intelligence**
**🔧 Tools:** `systeminfo` • `ipconfig`
- 🎯 **Purpose:** Baseline system configuration and network setup
- 📁 **Output:** System specs, hardware info, network adapters

### 🌐 **3. Network Forensics**
**🔧 Tools:** `netstat` • `tcpvcon` • `netsh` • DNS cache
- 🎯 **Purpose:** Active connections, network artifacts, communication patterns
- 📊 **Key Data:**
  - Live TCP/UDP connections with PIDs
  - DNS resolution history
  - Port forwarding rules
- 📁 **Output:** `netstat_abno.txt` • `tcpview.csv` • `dnscache.txt`

### 👥 **4. User & Access Analysis**
**🔧 Tools:** `net` • `PsLoggedon` • Directory analysis
- 🎯 **Purpose:** User activity, privilege escalation, account compromise
- 📊 **Key Data:**
  - Local users & administrators
  - Profile access patterns
  - Active login sessions
- 📁 **Output:** User lists, profile timestamps, session data

---

## 🔒 **Advanced Security Modules**

### 🎯 **5. Persistence Hunting**
**🔧 Arsenal:** `sigcheck` • `autorunsc` • `wmic` • Registry analysis

#### 🔍 **Digital Signature Verification:**
```
🎭 Accessibility Hijacking Targets:
├── displayswitch.exe    🖥️  Display switching utility
├── atbroker.exe        ♿  Assistive technology broker  
├── narrator.exe        🔊  Screen reader
├── magnify.exe         🔍  Screen magnifier
├── utilman.exe         🛠️  Utility manager
├── sethc.exe          ⌨️  Sticky keys
└── osk.exe            📱  On-screen keyboard
```

#### 🕵️ **Persistence Mechanisms:**
- **WMI Events:** Consumers, filters, bindings
- **Application Shims:** Custom compatibility layers
- **Startup Programs:** Complete autoruns analysis
- **Remote Tools:** PsExec service detection
- **Scheduled Tasks:** System & user task enumeration

### ⚙️ **6. Process Intelligence**
**🔧 Tools:** `wmic` • `pslist` • PowerShell CIM
- 🎯 **Deep Process Analysis:**
  - Complete process tree hierarchy
  - Command-line arguments & execution paths
  - Parent-child relationships
  - Process creation timestamps
- 📁 **Output:** Multi-format process data (TXT/CSV)

### 📋 **7. Event Log Collection**
**🔧 Sources:** Windows Event Logs (.evtx)

#### 🎯 **Critical Security Logs:**
```
🛡️  Security & Authentication:
├── Security.evtx               🔐 Login attempts, privilege use
├── System.evtx                ⚙️  System events, service changes
└── Application.evtx           📱 Application crashes, errors

🖥️  Remote Access & Management:
├── Terminal Services          🖱️  RDP connections & sessions
├── WinRM Operations          📡 Remote PowerShell activity
└── RDP Core Events           🔄 Remote desktop protocols

🔧 Advanced Monitoring:
├── PowerShell Logs           💻 Script execution, commands
├── SMB Client/Server         📂 File sharing activity  
├── Task Scheduler           ⏰ Scheduled task execution
├── WMI Activity             🔍 Management instrumentation
└── Sysmon (if available)    👁️ Enhanced system monitoring
```

### 💾 **8. File System Forensics**
**🔧 Tools:** `sigcheck` • PowerShell • Directory enumeration

#### 🔍 **Comprehensive Signature Analysis:**
```
🏛️  System Core:
├── C:\Windows\System32\        🛡️ Core system binaries
├── C:\Windows\System32\drivers\ 🚗 Kernel drivers
├── C:\Windows\SysWOW64\       🔄 32-bit compatibility layer
└── C:\Windows\temp\           🗂️ System temporary files

📦 Applications & Data:
├── C:\Program Files\          📱 Installed applications  
├── C:\Program Files (x86)\    📱 32-bit applications
├── C:\ProgramData\           🗃️ Application shared data
└── C:\Users\Public\          👥 Public user files

👤 User Artifacts:
├── AppData\Roaming\          ☁️  User application data
├── AppData\Local\            💻 Local application cache
├── AppData\Local\Temp\       🗑️  User temporary files
└── Downloads\                ⬇️  Downloaded files
```

---

## 📊 **Output Architecture**

```
📁 samples_[COMPUTERNAME]/
├── 🧬 hollows_hunter/          → Memory injection analysis
├── 📋 win-event-log/           → Security event archives  
├── 💾 SystemFiles/
│   ├── 🏛️ DefaultFolder/       → System-wide artifacts
│   └── 👤 UserFolder/          → User-specific data
├── 🌐 netstat_abno.txt        → Network connections
├── 🎯 autoruns.csv            → Persistence mechanisms
├── ⚙️ process_tree.txt        → Process hierarchy
└── 📊 [various analysis files]
```

---

## 🚀 **Features & Capabilities**

| Feature | Description |
|---------|-------------|
| 🏗️ **Auto-Architecture** | Automatically detects x64/x86 and uses appropriate tools |
| ⚡ **PowerShell Enhanced** | Advanced data collection when PowerShell is available |
| 📝 **Comprehensive Logging** | Detailed error tracking and operation logs |
| 📊 **Progress Monitoring** | Real-time progress visualization |
| 🛠️ **Sysinternals Integration** | Leverages Microsoft Sysinternals suite |
| 🔒 **Privilege Aware** | Optimized for administrative access |

---

## 🎯 **Use Cases**

- 🚨 **Incident Response:** Rapid triage and evidence collection
- 🔍 **Threat Hunting:** Proactive security analysis
- 🛡️ **Digital Forensics:** Comprehensive system examination  
- 🔒 **Security Assessment:** System hardening verification

---

## ⚡ **Quick Start**

1. **Run as Administrator** for full system access
2. **Select Module** from interactive menu (1-9)
3. **Monitor Progress** via real-time progress bar
4. **Review Results** in organized output directory

> 💡 **Pro Tip:** Use option `9` to run all modules for comprehensive analysis
