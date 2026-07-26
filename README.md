# 🛡️ CyberNexsus

> **AI-Powered Security Operations Center (SOC)**

CyberNexsus is an AI-powered Security Operations Center (SOC) that integrates **Splunk Enterprise**, **Windows Event Logs**, **Sysmon**, **Linux Logs**, **Zeek**, and **Suricata** to provide centralized threat monitoring, AI-assisted investigation, risk scoring, MITRE ATT&CK mapping, and real-time Telegram alerts.

---

## 📌 Features

* Windows Event Log Monitoring
* Sysmon Event Collection
* Linux Log Monitoring
* Zeek Network Traffic Analysis
* Suricata Intrusion Detection System (IDS)
* Splunk Enterprise SIEM Integration
* AI-Based Threat Investigation
* Dynamic Risk Scoring
* MITRE ATT&CK Mapping
* Telegram Alert Notifications
* React Dashboard
* Node.js Backend

---

## 🏗️ Architecture

```text
Windows VM (Sysmon + Event Logs)
            │
            ▼
Linux VM (System Logs)
            │
            ▼
Network Traffic
     ├── Zeek
     └── Suricata
            │
            ▼
     Splunk Enterprise
            │
            ▼
     CyberNexsus AI Engine
            │
     ├── React Dashboard
     ├── Telegram Alerts
     ├── Risk Score
     └── MITRE ATT&CK Mapping
```

---

# 🛠️ Technology Stack

## Frontend

* React
* TypeScript
* Tailwind CSS
* Vite

## Backend

* Node.js
* Express.js

## SIEM

* Splunk Enterprise
* Splunk Universal Forwarder

## Network Security

* Zeek
* Suricata

## AI

* OpenRouter API
* Llama 3.3 70B

## Notifications

* Telegram Bot API

---

# 📋 Prerequisites

* Ubuntu/Kali Linux
* Windows 10/11 VM
* Node.js 20+
* Git
* Python 3
* Splunk Enterprise
* Splunk Universal Forwarder

---

# 📥 Clone Repository

```bash
git clone https://github.com/RAMU5653/CyberNexsus.git

cd CyberNexsus
```

---

# ⚙️ Backend Installation

```bash
cd backend

npm install
```

---

# 💻 Frontend Installation

```bash
cd frontend

npm install
```

---

# 🔑 Configure Environment Variables

Create a `.env` file inside the backend folder.

```env
OPENROUTER_API_KEY=your_openrouter_api_key

SPLUNK_HOST=https://localhost:8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your_password

BOT_TOKEN=your_telegram_bot_token
CHAT_ID=your_telegram_chat_id
```

---

# 📊 Install Splunk Enterprise

Start Splunk:

```bash
sudo /opt/splunk/bin/splunk start --run-as-root
```

Enable boot start:

```bash
sudo /opt/splunk/bin/splunk enable boot-start --accept-license --answer-yes --no-prompt
```

---

# 🔄 Install Splunk Universal Forwarder

Install Splunk Universal Forwarder on Windows and Linux.

Configure `outputs.conf`:

```ini
[tcpout]
defaultGroup=indexer

[tcpout:indexer]
server=<Splunk_Server_IP>:9997
```

Restart the Universal Forwarder after configuration.

---

# 🌐 Install Zeek

Update packages:

```bash
sudo apt update

sudo apt upgrade -y
```

Install dependencies:

```bash
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 zlib1g-dev swig
```

Clone Zeek:

```bash
git clone --recursive https://github.com/zeek/zeek.git

cd zeek
```

Build Zeek:

```bash
mkdir build

cd build

cmake ..

make -j$(nproc)

sudo make install
```

Add Zeek to PATH:

```bash
echo 'export PATH=/usr/local/zeek/bin:$PATH' >> ~/.bashrc

source ~/.bashrc
```

Verify installation:

```bash
zeek --version
```

---

# 🚀 Deploy Zeek

Deploy Zeek:

```bash
sudo /usr/local/zeek/bin/zeekctl deploy
```

Check status:

```bash
sudo /usr/local/zeek/bin/zeekctl status
```

View running nodes:

```bash
sudo /usr/local/zeek/bin/zeekctl top
```

Zeek logs are stored in:

```text
/usr/local/zeek/logs/current/
```

Verify logs:

```bash
ls -lah /usr/local/zeek/logs/current/
```

---

# 🛡️ Install Suricata

```bash
sudo apt update

sudo apt install -y suricata
```

Verify installation:

```bash
suricata --build-info
```

Enable and start Suricata:

```bash
sudo systemctl enable suricata

sudo systemctl start suricata

sudo systemctl status suricata
```

Suricata logs are stored in:

```text
/var/log/suricata/
```

---

# 📂 Configure Splunk Inputs

Monitor Zeek logs:

```ini
[monitor:///usr/local/zeek/logs/current]
index = network
sourcetype = zeek
```

Monitor Suricata logs:

```ini
[monitor:///var/log/suricata/eve.json]
index = network
sourcetype = suricata:json
```

Restart Splunk:

```bash
sudo /opt/splunk/bin/splunk restart
```

---

# ✅ Verify Data in Splunk

Zeek:

```spl
index=network sourcetype=zeek
```

Suricata:

```spl
index=network sourcetype=suricata:json
```

Windows:

```spl
index=windows
```

Linux:

```spl
index=linux
```

---

# ▶️ Run Backend

```bash
cd backend

npm run dev
```

---

# ▶️ Run Frontend

```bash
cd frontend

npm run dev
```

---

# 🌍 Dashboard

Open your browser:

```text
http://localhost:3000
```

---

# 📁 Project Structure

```text
CyberNexsus/
├── backend/
├── frontend/
├── README.md
├── LICENSE
└── docs/
```

---

# 🚀 Future Enhancements

* Microsoft Sentinel Integration
* Elastic Stack Support
* SOAR Automation
* Threat Intelligence Integration
* Email Alerts
* Mobile Application
* AI SOC Assistant
* Threat Hunting Module
* Case Management

---

# 🤝 Contributing

Contributions are welcome. Fork the repository, create a feature branch, commit your changes, and open a Pull Request.

---

# 📄 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

**Venkataram Gumma**

GitHub: https://github.com/RAMU5653

---

# ⭐ Support

If you found this project useful, please consider giving it a ⭐ on GitHub.

