# 🛡️ CyberNexsus

## AI-Powered Cybersecurity and SOC Threat Detection Platform

CyberNexsus is an AI-powered cybersecurity platform designed to support both **Security Operations Center (SOC) analysts** and **normal users**.

The platform collects and analyzes security events from multiple sources, calculates a local risk score, investigates suspicious activity using AI, and provides security alerts through Telegram.

CyberNexsus also includes a **Normal User Security Mode**, allowing users to submit suspicious messages, phishing attempts, URLs, emails, or other content for basic security analysis.

---

# 📌 Project Overview

Modern cybersecurity threats affect both organizations and ordinary users.

SOC analysts need to investigate large volumes of security logs, while normal users may receive phishing emails, suspicious messages, scam links, OTP requests, and account-related threats.

CyberNexsus provides two major modes:

1. 🧑‍💻 **SOC Analyst Mode**
2. 📱 **Normal User Mode**

```text
                    ┌─────────────────────┐
                    │    CyberNexsus      │
                    │ AI Cybersecurity    │
                    │     Platform        │
                    └──────────┬──────────┘
                               │
                ┌──────────────┴──────────────┐
                │                             │
                ▼                             ▼
       🧑‍💻 SOC Analyst Mode            📱 Normal User Mode
                │                             │
                ▼                             ▼
          Splunk Logs                  Suspicious Content
                │                             │
                ▼                             ▼
          Risk Engine                    Basic Analysis
                │                             │
                ▼                             ▼
          Featherless AI                Security Report
                │                             │
                ▼                             ▼
        Investigation Report           Simple Safety Advice
                │
                ▼
          Telegram Alerts
```

---

# ✨ Features

## 🧑‍💻 SOC Analyst Mode

- Windows security log monitoring
- Linux authentication log monitoring
- Sysmon event analysis
- SSH brute-force detection
- Port scan detection
- Suspicious process detection
- Network security monitoring
- Suricata alert monitoring
- Zeek network log monitoring
- USB/removable device monitoring
- Sensitive file activity detection
- Data exfiltration risk detection
- Local risk scoring
- AI-assisted incident investigation
- MITRE ATT&CK mapping
- Automated remediation recommendations
- Telegram security alerts

---

## 📱 Normal User Mode

Normal users can submit suspicious content such as:

- Suspicious SMS messages
- Phishing emails
- Scam messages
- Suspicious URLs
- OTP requests
- Fake prize messages
- Account suspension messages
- Credential theft attempts

Example:

```text
User:
"Your bank account will be blocked immediately.
Click here and enter your OTP."

        ↓

CyberNexsus Analysis

        ↓

⚠️ Possible Security Threat

Risk Score: 70/100
Severity: HIGH

Indicators:
• Urgency language detected
• Requests sensitive authentication information
• Account threat or suspension claim detected

Recommended Action:
❌ Do not click suspicious links
❌ Do not share OTPs or passwords
✅ Contact the organization using official channels
```

---

# 🏗️ System Architecture

## Complete Architecture

```text
                         INTERNET
                            │
                            ▼
                  ┌───────────────────┐
                  │   Telegram Bot    │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  CyberNexsus API  │
                  │ Node.js + Express │
                  └─────────┬─────────┘
                            │
          ┌─────────────────┴──────────────────┐
          │                                    │
          ▼                                    ▼
 ┌─────────────────┐                 ┌─────────────────┐
 │  SOC ANALYST    │                 │  NORMAL USER    │
 │      MODE       │                 │      MODE       │
 └────────┬────────┘                 └────────┬────────┘
          │                                    │
          ▼                                    ▼
 ┌─────────────────┐                 ┌─────────────────┐
 │ Splunk SIEM     │                 │ User Content    │
 │ Security Logs   │                 │ Analysis        │
 └────────┬────────┘                 └────────┬────────┘
          │                                    │
          ▼                                    ▼
 ┌─────────────────┐                 ┌─────────────────┐
 │ Risk Engine     │                 │ Basic Security  │
 │                 │                 │ Checks          │
 └────────┬────────┘                 └────────┬────────┘
          │                                    │
          └─────────────────┬──────────────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  Featherless AI   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Security Analysis │
                  │ & Recommendations │
                  └───────────────────┘
```

---

# 💻 Technology Stack

## Frontend

- React
- TypeScript
- Vite
- CSS

## Backend

- Node.js
- Express.js
- TypeScript

## AI

- Featherless AI
- OpenAI-compatible API

## SIEM

- Splunk Enterprise

## Security Tools

- Sysmon
- Zeek
- Suricata
- Splunk Universal Forwarder

## Infrastructure

- Kali Linux
- Windows 10
- VMware

## Alerting

- Telegram Bot API

---

# 🔍 SOC Analyst Architecture

```text
Windows 10
     │
     │ Windows Events + Sysmon
     ▼
Splunk Universal Forwarder
     │
     │ TCP 9997
     ▼
Kali Linux
     │
     ▼
Splunk Enterprise
     │
     ▼
CyberNexsus Risk Engine
     │
     ▼
Featherless AI
     │
     ▼
Incident Investigation
     │
     ▼
Telegram Alert
```

---

# 🪟 Windows 10 Configuration

The Windows machine acts as an endpoint that generates security telemetry.

## Required Components

- Windows Event Logs
- Sysmon
- Splunk Universal Forwarder

Example Splunk Universal Forwarder configuration:

```ini
[WinEventLog://Security]
disabled = 0
index = windows-10

[WinEventLog://System]
disabled = 0
index = windows-10

[WinEventLog://Application]
disabled = 0
index = windows-10

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows-10
```

Example output configuration:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = KALI_IP_ADDRESS:9997
```

---

# 🐉 Kali Linux Configuration

Kali Linux runs the main security infrastructure.

## Components

- Splunk Enterprise
- CyberNexsus Backend
- Zeek
- Suricata
- Node.js

---

## Splunk Receiving Port

Enable the Splunk receiving port:

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth USERNAME:PASSWORD
```

Verify the port:

```bash
sudo ss -tulpn | grep 9997
```

---

## Create Splunk Indexes

```bash
sudo /opt/splunk/bin/splunk add index windows-10
sudo /opt/splunk/bin/splunk add index linux
sudo /opt/splunk/bin/splunk add index network
```

Verify:

```bash
sudo /opt/splunk/bin/splunk list index
```

---

# 📊 Splunk Index Architecture

```text
┌───────────────────┐
│    windows-10     │
├───────────────────┤
│ Windows Events    │
│ Security Logs     │
│ Sysmon Events     │
└───────────────────┘

┌───────────────────┐
│       linux       │
├───────────────────┤
│ Authentication    │
│ System Logs       │
│ Kernel Logs       │
└───────────────────┘

┌───────────────────┐
│      network      │
├───────────────────┤
│ Suricata Alerts   │
│ Zeek Logs         │
│ Network Events    │
└───────────────────┘
```

---

# 📈 Risk Scoring Engine

CyberNexsus uses a local risk engine to calculate the security score.

The risk score is the authoritative security measurement.

AI does not override the local risk score.

## Example Risk Factors

| Detection | Risk Contribution |
|---|---:|
| Failed Login | Variable |
| SSH Brute Force | High |
| Successful Login After Brute Force | High |
| Port Scan | High |
| Suspicious Sysmon Activity | Medium/High |
| Malware or Exploit Alert | High |
| Privileged Activity | Medium |
| USB Activity | Medium |
| Sensitive File Activity | High |
| Potential Data Exfiltration | Critical |

Risk scores are limited between:

```text
0 ───────────────────────── 100
```

Severity levels:

```text
0 - 24   → LOW
25 - 49  → MEDIUM
50 - 74  → HIGH
75 - 100 → CRITICAL
```

---

# 🤖 AI Investigation

When security events reach the required threshold, CyberNexsus sends relevant evidence to Featherless AI.

The AI generates:

- Incident title
- Security summary
- Technical details
- Timeline
- MITRE ATT&CK mapping
- Recommended remediation steps

Example:

```text
Splunk Detection
       │
       ▼
Local Risk Score
       │
       ▼
Security Evidence
       │
       ▼
Featherless AI
       │
       ▼
Incident Report
```

---

# 📱 Normal User Mode

The Normal User Mode allows ordinary users to submit suspicious content.

## Workflow

```text
Normal User
     │
     ▼
Suspicious Message / Email / URL
     │
     ▼
CyberNexsus API
     │
     ▼
Basic Security Analysis
     │
     ├── URL Detection
     ├── OTP Request Detection
     ├── Urgency Language
     ├── Password Requests
     ├── Account Threats
     └── Prize/Reward Scams
     │
     ▼
Risk Score
     │
     ▼
Simple Security Report
```

---

# 🔌 API Endpoints

## Splunk Connection Test

```text
GET /api/splunk/test
```

## Get Splunk Logs

```text
GET /api/splunk/logs
```

## Get Splunk Statistics

```text
GET /api/splunk/stats
```

## Analyze Security Events

```text
POST /api/threats/analyze
```

## Splunk Webhook

```text
POST /api/alerts/splunk
```

## Test Telegram

```text
GET /api/test/telegram
```

## Normal User Security Analysis

```text
POST /api/user/analyze
```

Example request:

```json
{
  "text": "Your account will be blocked immediately. Click here and enter your OTP."
}
```

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CyberNexsus.git
```

```bash
cd CyberNexsus
```

---

## 2. Install Dependencies

```bash
npm install
```

---

## 3. Configure Environment Variables

Create a `.env` file:

```bash
nano .env
```

Example configuration:

```env
PORT=3000

FEATHERLESS_API_KEY=YOUR_API_KEY

TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
TELEGRAM_GROUP_CHAT_ID=YOUR_GROUP_ID
TELEGRAM_PERSONAL_CHAT_ID=YOUR_PERSONAL_CHAT_ID

SPLUNK_HOST=127.0.0.1
SPLUNK_PORT=8089
SPLUNK_USER=YOUR_SPLUNK_USERNAME
SPLUNK_PASSWORD=YOUR_SPLUNK_PASSWORD

ENABLE_SPLUNK_POLLING=true
```

⚠️ **Never upload the `.env` file to GitHub.**

---

# ▶️ Running the Project

Start the development server:

```bash
npm run dev
```

The application will run on:

```text
http://localhost:3000
```

---

# 🔐 Security Considerations

- API keys must be stored in `.env`
- Never commit credentials to GitHub
- Rotate exposed API keys immediately
- Protect Splunk webhook endpoints
- Use strong passwords
- Validate all user input
- Limit request sizes
- Use HTTPS for production deployments
- Review AI-generated security conclusions before taking destructive actions

---

# 📁 Project Structure

```text
CyberNexsus/
│
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── index.css
│   ├── types.ts
│   └── services/
│       └── splunk.ts
│
├── server.ts
├── package.json
├── package-lock.json
├── vite.config.ts
├── tsconfig.json
├── .env.example
├── .gitignore
└── README.md
```

---

# 🚀 Future Enhancements

- Telegram-based Normal User Mode
- Automatic phishing URL reputation checking
- File hash analysis
- VirusTotal integration
- Email header analysis
- Screenshot analysis
- Voice-based cybersecurity assistant
- Telugu language support
- Real-time threat intelligence feeds
- Automatic incident ticket creation
- PDF security reports
- Advanced dashboard analytics

---

# 🎯 Project Objective

The objective of CyberNexsus is to create a unified cybersecurity platform that makes security assistance accessible to both:

- **SOC analysts investigating enterprise threats**
- **Normal users facing phishing and scam attacks**

```text
        Enterprise Security
                +
        Personal Cyber Safety
                +
           Artificial Intelligence
                =
           CyberNexsus
```

---

# 👨‍💻 Author

**Gumma Venkataram**

B.Tech Computer Science Engineering  
Specialization: Cyber Security

---

# ⚠️ Disclaimer

CyberNexsus is developed for educational, research, and authorized cybersecurity purposes.

The security analysis generated by this project should be treated as assistance and not as a guarantee that content is safe or malicious.

Always verify important security decisions using trusted security tools and official sources.
