# 🔍 CyberVenator Suite Tool


Công cụ phân tích bảo mật được thiết kế cho điều tra số, ứng phó sự cố và săn lùng mối đe dọa trên  Windows.

---

## 🧬 **Module 1: Kiểm tra Process Injection**

**🔧 Công cụ:** HollowsHunter (32-bit/64-bit)

### Chi tiết hoạt động:
- **Mục đích:** Phát hiện code injection, process hollowing, và thao tác bộ nhớ
- **Cách thức:** Quét tất cả process đang chạy, phân tích bộ nhớ tìm dấu hiệu bị inject
- **Kỹ thuật phát hiện:**
  - Process Hollowing (thay thế nội dung process hợp pháp)
  - DLL Injection (tiêm thư viện độc hại)
  - Reflective DLL Loading
  - Manual DLL mapping
  - Thread hijacking

### Output files:
```
hollows_hunter/
├── hollows_hunter.csv        → Báo cáo tổng quan các process nghi vấn
├── [PID].exe                → Memory dump của process bị nhiễm  
├── [PID].shc                → Shellcode được trích xuất
└── [PID].dll                → DLL bị inject (nếu có)
```

---

## 🖥️ **Module 2: Thu thập Thông tin Hệ thống**

**🔧 Công cụ:** `systeminfo.exe`, `ipconfig.exe`

### Chi tiết thu thập:
**System Information (`systeminfo.txt`):**
- Tên máy tính, domain/workgroup
- Phiên bản Windows, build number, architecture
- Thông tin phần cứng: CPU, RAM, motherboard
- Danh sách hotfix/patch đã cài đặt
- Thời gian boot lần cuối
- Múi giờ hệ thống

**Network Configuration (`ipconfig_all.txt`):**
- Tất cả network adapter (active/inactive)
- IP address, subnet mask, gateway
- DNS servers, DHCP configuration
- MAC addresses
- DHCP lease information

### Tại sao quan trọng:
- Xác định baseline hệ thống
- Phát hiện patch missing (lỗ hổng bảo mật)
- Hiểu cấu hình mạng cho lateral movement analysis

---

## 🌐 **Module 3: Điều tra Mạng**

**🔧 Công cụ:** `netstat`, `tcpvcon`, `netsh`, `ipconfig`

### Chi tiết thu thập:

**Active Connections (`netstat_abno.txt`):**
```bash
# Flags giải thích:
# -a: Hiển thị tất cả connections và listening ports
# -b: Hiển thị executable tạo ra connection
# -n: Hiển thị địa chỉ IP thay vì resolve hostname  
# -o: Hiển thị Process ID (PID)
```

**Thông tin bao gồm:**
- TCP/UDP connections với process name và PID
- Listening ports và service đang bind
- Foreign addresses (địa chỉ kết nối tới)
- Connection state (ESTABLISHED, LISTENING, etc.)

**DNS Cache (`dnscache.txt`):**
- Lịch sử domain được resolve
- TTL (Time To Live) của các DNS records
- Phát hiện domain độc hại đã được truy vấn

**Port Proxy (`portproxy.txt`):**
- Cấu hình port forwarding
- Phát hiện tunneling techniques
- Network redirection rules

**TCP View (`tcpview.csv`):**
- Real-time network connections với timestamps
- Process path và command line
- Connection duration

### Ý nghĩa forensics:
- Phát hiện backdoor connections
- Identify command & control (C2) communications  
- Network lateral movement evidence
- Data exfiltration channels

---

## 👥 **Module 4: Phân tích User và Quyền truy cập**

**🔧 Công cụ:** `net.exe`, `PsLoggedon`, directory analysis

### Chi tiết thu thập:

**Local Users (`local_users_list.txt`):**
```cmd
net localgroup users
```
- Danh sách tất cả user accounts local
- Built-in accounts và user-created accounts
- Account status (active/disabled)

**Local Administrators (`local_admin_list.txt`):**
```cmd  
net localgroup administrators
```
- Members của group Administrators
- Phát hiện privilege escalation
- Unauthorized admin accounts

**User Profile Analysis:**
- `local_users_dir_created.txt`: Thời gian tạo user profiles
- `local_users_dir_modified.txt`: Thời gian truy cập gần nhất
- Pattern analysis cho user activity

**Currently Logged Users (`logged_on_users.txt`):**
- Interactive logon sessions
- Network logon sessions  
- Service account sessions
- Logon time và session type

### Red flags cần chú ý:
- User accounts tạo gần đây
- Accounts với admin privileges bất thường
- Multiple concurrent sessions từ same user
- Service accounts với interactive logons

---

## 🎯 **Module 5: Săn lùng Persistence (Chi tiết)**

**🔧 Arsenal:** `sigcheck`, `autorunsc`, `wmic`, Registry analysis

### 5.1 Digital Signature Verification

**Accessibility Tools Hijacking:**
```
Tại sao check những file này?
├── sethc.exe          → Sticky Keys (F5 5 lần)
├── utilman.exe        → Utility Manager (Win+U)  
├── magnify.exe        → Magnifier (Win++)
├── narrator.exe       → Narrator (Win+Enter)
├── displayswitch.exe  → Display Switch (Win+P)
├── atbroker.exe       → AT Broker
└── osk.exe           → On-Screen Keyboard (Win+Ctrl+O)
```

**Tại sao attacker target các file này:**
- Có thể gọi từ login screen (trước khi đăng nhập)
- Chạy với SYSTEM privileges
- Kỹ thuật phổ biến: thay thế bằng cmd.exe hoặc backdoor

**Kiểm tra thực hiện:**
- File signature verification (Microsoft signed?)
- File hash comparison với known good values
- File size và timestamp analysis
- Cả System32 và SysWOW64 (trên x64)

### 5.2 WMI Persistence

**Event Consumers (`wmi_event_consumer.txt`):**
- Script event consumers (chạy VBScript/JScript)
- Command line event consumers (chạy commands)
- ActiveScript event consumers

**Event Filters (`wmi_event_filter.txt`):**
- Trigger conditions (system startup, logon, etc.)
- SQL-like queries defining when to activate
- Temporal filters (time-based triggers)

**Filter-Consumer Bindings (`wmi_filter_consumer_binding.txt`):**
- Liên kết giữa trigger và action
- Persistence mechanism hoàn chỉnh

### 5.3 Application Compatibility Shims

**Registry Keys:**
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`

**Shim Database Files:**
- `C:\Windows\AppPatch\Custom\` - Custom shim databases
- `C:\Windows\AppPatch\Custom\Custom64\` - x64 shims

**Mục đích của attacker:**
- DLL redirection  
- API hooking
- Bypass security controls
- Process injection via shims

### 5.4 Startup Programs Analysis

**AutoRuns (`autoruns.csv`):**
```
Categories được scan:
├── Registry Run Keys         → HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run
├── Startup Folders          → User và All Users startup folders  
├── Services                 → Windows services auto-start
├── Drivers                  → Kernel và filesystem drivers
├── Scheduled Tasks          → Task Scheduler entries
├── Winlogon                 → Shell, userinit, notify packages
├── Internet Explorer        → Browser Helper Objects, toolbars
├── AppInit DLLs            → DLLs loaded into every process
├── Image Hijacks           → Image File Execution Options
├── Boot Execute            → Native API programs
└── LSA Providers           → Authentication packages
```

### 5.5 PsExec Detection

**Artifacts tìm kiếm:**
- `C:\Windows\PSEXESVC.exe` - PsExec service binary
- Registry: `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC`
- Service status và configuration
- File timestamps (creation/modification)

---

## ⚙️ **Module 6: Intelligence Process**

**🔧 Công cụ:** `wmic`, `pslist`, PowerShell CIM

### Chi tiết thu thập:

**WMIC Process List (`process_txt.txt`, `process_csv.csv`):**
```cmd
wmic process list full
```
**Thông tin chi tiết mỗi process:**
- Process name, PID, PPID (Parent Process ID)
- Command line đầy đủ
- Executable path
- Process owner (user context)
- Memory usage, thread count
- Creation date/time
- Session ID

**Process Tree (`process_tree.txt`):**
```cmd  
pslist -t
```
- Hierarchical view của parent-child relationships
- Phát hiện process injection techniques
- Identify suspicious process spawning patterns

**PowerShell Enhanced (`system_processes.csv`):**
```powershell
Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId, CreationDate
```

### Red flags trong process analysis:
- Processes chạy từ temp directories
- Unsigned executables in system locations  
- Unusual parent-child relationships
- Processes với command lines dài/mã hóa
- System processes chạy từ wrong locations

---

## 📋 **Module 7: Thu thập Event Logs (Chi tiết)**

**🔧 Source:** Windows Event Logs (.evtx files)

### 7.1 Security & Authentication Logs

**Security.evtx:**
```
Event IDs quan trọng:
├── 4624 → Successful logon
├── 4625 → Failed logon  
├── 4648 → Logon with explicit credentials
├── 4672 → Special privileges assigned
├── 4720 → User account created
├── 4726 → User account deleted
├── 4738 → User account changed
├── 4771 → Kerberos pre-authentication failed
└── 4776 → NTLM authentication
```

**System.evtx:**
```
Event categories:
├── Service installations/changes
├── System startup/shutdown
├── Driver loading events  
├── Time changes
├── System crashes
└── Hardware events
```

**Application.evtx:**
```
Application logs:
├── Software crashes
├── Application errors
├── Installation events
└── Custom application logs
```

### 7.2 Remote Access Logs

**Terminal Services:**
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`
- `Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx`

**Key RDP Events:**
```
Event IDs:
├── 21 → Remote Desktop Services: Session logon succeeded
├── 22 → Remote Desktop Services: Shell start notification
├── 23 → Remote Desktop Services: Session logoff succeeded  
├── 24 → Remote Desktop Services: Session disconnected
└── 25 → Remote Desktop Services: Session reconnection succeeded
```

### 7.3 PowerShell Monitoring

**Windows PowerShell.evtx:**
- PowerShell engine startup/shutdown
- Module loading events
- Provider lifecycle events

**Microsoft-Windows-PowerShell%4Operational.evtx:**
```
Event IDs:
├── 4103 → Module logging (command execution)
├── 4104 → Script block logging (code executed)  
├── 4105 → Script block logging start
├── 4106 → Script block logging stop
└── 53504 → PowerShell execution policy change
```

### 7.4 Network & File Sharing

**SMB Logs:**
- `Microsoft-Windows-SmbClient%4Security.evtx`
- `Microsoft-Windows-SMBServer%4Security.evtx`

**WinRM Logs:**
- `Microsoft-Windows-WinRM%4Operational.evtx`
- Remote PowerShell sessions
- WS-Management activities

### 7.5 Advanced Monitoring

**Sysmon (nếu có):**
- `Microsoft-Windows-Sysmon%4Operational.evtx`
```
Sysmon Event Types:
├── Event 1  → Process creation
├── Event 2  → File creation time changed
├── Event 3  → Network connection
├── Event 5  → Process terminated
├── Event 7  → Image/library loaded
├── Event 8  → CreateRemoteThread detected
├── Event 11 → File created
├── Event 12 → Registry object added/deleted
└── Event 13 → Registry value set
```

---

## 💾 **Module 8: File System Forensics (Chi tiết)**

**🔧 Công cụ:** `sigcheck`, PowerShell, Directory enumeration

### 8.1 System Core Analysis

**C:\Windows\System32\ (`detail_system32.csv`):**
```cmd
sigcheck -s -ct -h -a -nobanner C:\Windows\System32
```
**Flags explanation:**
- `-s`: Recurse subdirectories
- `-ct`: Show certificate thumbprint  
- `-h`: Show hashes (MD5, SHA1, SHA256)
- `-a`: Show extended version info

**Thông tin thu thập:**
- File signatures (Microsoft signed?)
- Version information
- File hashes cho integrity checking
- Creation/modification timestamps
- Certificate validity

**C:\Windows\System32\drivers\ (`detail_drivers.csv`):**
- Kernel drivers analysis
- Unsigned drivers (red flag)
- Recently modified drivers
- Driver file integrity

### 8.2 Application Directories

**C:\Program Files\ & C:\Program Files (x86)\:**
```powershell
Get-ChildItem -Path "C:\Program Files" -Force | 
Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName |
Sort-Object -Property LastWriteTime
```

**Analysis focus:**
- Recently installed software
- Unsigned executables
- Software in unusual locations
- Portable applications (không cài đặt)

### 8.3 Temporary Directories

**C:\Windows\Temp\ & User Temp folders:**
- Malware staging areas
- Dropped files từ exploitation
- Persistence mechanisms
- Evidence of recent activity

### 8.4 User Profile Analysis

**Cho mỗi user profile:**

**AppData\Roaming\:**
- Application settings
- Browser data
- Email clients
- Persistence locations

**AppData\Local\:**
- Local application caches
- Browser cache và history
- Application logs

**AppData\Local\Temp\:**
- User-specific temporary files
- Downloaded malware
- Extraction directories

**Downloads\:**
- Recently downloaded files
- Browser download history
- Potential malware entry points

### PowerShell Analysis Script:
```powershell
$files = Get-ChildItem -Path $targetPath -Force -ErrorAction SilentlyContinue
$files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName |
Sort-Object -Property LastWriteTime |
Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
```

---

## 📊 **Cấu trúc Output chi tiết**

```
📁 samples_[COMPUTERNAME]/
├── 🧬 hollows_hunter/
│   ├── hollows_hunter.csv           → Summary report
│   ├── [PID].exe                   → Dumped executables  
│   ├── [PID].shc                   → Extracted shellcode
│   └── [PID].dll                   → Injected DLLs
│
├── 📋 win-event-log/
│   ├── Security.evtx               → Authentication events
│   ├── System.evtx                 → System events
│   ├── Application.evtx            → Application logs
│   ├── Windows PowerShell.evtx     → PowerShell activity
│   ├── Microsoft-Windows-PowerShell%4Operational.evtx
│   └── [other security logs...]
│
├── 💾 SystemFiles/
│   ├── 🏛️ DefaultFolder/
│   │   ├── systemdrive.csv         → C:\ contents
│   │   ├── Windows.csv             → Windows folder
│   │   ├── System32.csv            → System32 files
│   │   ├── detail_system32.csv     → Signatures + hashes
│   │   ├── drivers.csv             → Driver files
│   │   ├── detail_drivers.csv      → Driver signatures
│   │   └── [other system locations...]
│   │
│   └── 👤 UserFolder/
│       ├── [Username]/
│       │   ├── roaming.csv         → AppData\Roaming
│       │   ├── detail_roaming.csv  → Roaming signatures
│       │   ├── local.csv           → AppData\Local
│       │   ├── temp.csv            → Temp folder
│       │   └── downloads.csv       → Downloads folder
│       └── [Other users...]
│
├── 📊 Network Analysis/
│   ├── netstat_abno.txt            → Active connections
│   ├── tcpview.csv                 → TCP connections detail
│   ├── dnscache.txt                → DNS resolution history
│   └── portproxy.txt               → Port forwarding rules
│
├── 🎯 Persistence Analysis/
│   ├── autoruns.csv                → All startup items
│   ├── sigcheck_system32_*.txt     → Accessibility tools check
│   ├── wmi_event_consumer.txt      → WMI consumers
│   ├── wmi_filter_consumer_binding.txt → WMI bindings
│   └── [other persistence artifacts...]
│
├── ⚙️ Process Analysis/
│   ├── process_txt.txt             → WMIC process list
│   ├── process_csv.csv             → Process data CSV
│   ├── process_tree.txt            → Process hierarchy
│   └── system_processes.csv        → PowerShell process data
│
└── 🖥️ System Baseline/
    ├── systeminfo.txt              → System configuration
    ├── ipconfig_all.txt            → Network configuration
    ├── local_users_list.txt        → Local users
    ├── local_admin_list.txt        → Local administrators
    └── logged_on_users.txt         → Current sessions
```

---

## 🚀 **Tính năng & Khả năng**

| Tính năng | Mô tả chi tiết |
|-----------|----------------|
| 🏗️ **Auto-Architecture Detection** | Tự động phát hiện x64/x86, sử dụng tools phù hợp (hollows_hunter64.exe vs hollows_hunter32.exe) |
| ⚡ **PowerShell Enhanced Collection** | Sử dụng PowerShell CIM/WMI cho data collection nâng cao khi available |
| 📝 **Comprehensive Error Logging** | Tất cả errors được log vào `error.txt` với timestamps |
| 📊 **Real-time Progress Monitoring** | Progress bar hiển thị tiến độ từng module |
| 🛠️ **Sysinternals Integration** | Tích hợp  Sysinternals Suite (PsLoggedon, TCPView, Autoruns, etc.) |
| 🔒 **Privilege-Aware Operations** | Tối ưu cho administrator access, graceful degradation nếu thiếu quyền |
| 🎯 **Selective Module Execution** | Có thể chạy từng module riêng lẻ hoặc tất cả |
| 📦 **Portable Design** | Self-contained, không cần installation |

---


