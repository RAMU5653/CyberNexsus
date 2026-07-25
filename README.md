# CyberNexsus – AI Powered SOC Monitoring Platform

CyberNexsus is an AI-powered Security Operations Center (SOC) prototype that collects logs from Windows, Linux, and Network devices using Splunk and performs automated threat analysis using AI. The platform visualizes security events on a dashboard and sends high-severity alerts to Telegram.

---

## Features

- AI-powered incident investigation
- Splunk SIEM integration
- Windows Event Log monitoring
- Sysmon log analysis
- Linux log monitoring
- Network log analysis
- MITRE ATT&CK mapping
- Risk score calculation
- Interactive SOC dashboard
- Telegram alert notifications
- Automated security event correlation

---

## Technology Stack

### Frontend

- React
- TypeScript
- Vite

### Backend

- Node.js
- Express.js
- TypeScript

### Security

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Logs
- Linux Logs

### AI

- OpenRouter API
- Llama 3.3 70B

---

## Project Structure

```
CyberNexsus/
│
├── src/
├── assets/
├── dist/
├── server.ts
├── package.json
├── tsconfig.json
└── README.md
```

---

## Prerequisites

- Node.js 20+
- Splunk Enterprise
- Splunk Universal Forwarder
- OpenRouter API Key
- Telegram Bot Token

---

## Installation

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/CyberNexsus.git
```

Move into the project

```bash
cd CyberNexsus
```

Install dependencies

```bash
npm install
```

---

## Configure Environment Variables

Create a `.env` file in the project root.

Example:

```env
PORT=3000

OPENROUTER_API_KEY=YOUR_OPENROUTER_API_KEY

TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
TELEGRAM_GROUP_CHAT_ID=YOUR_GROUP_CHAT_ID

SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USER=YOUR_SPLUNK_USERNAME
SPLUNK_PASSWORD=YOUR_SPLUNK_PASSWORD
```

---

## Run the Project

Development Mode

```bash
npm run dev
```

Production Build

```bash
npm run build
npm start
```

---

## Dashboard

Open your browser

```
http://localhost:3000
```

---

## API Endpoints

### Test Splunk

```
GET /api/splunk/test
```

### Latest Logs

```
GET /api/splunk/logs
```

### Log Statistics

```
GET /api/splunk/stats
```

### Analyze Threats

```
POST /api/threats/analyze
```

### Telegram Test

```
GET /api/test/telegram
```

---

## Workflow

```
Windows
      │
      │
Linux ├────► Splunk Enterprise
      │
Network
      │
      ▼
CyberNexsus Backend
      │
      ▼
OpenRouter AI
      │
      ▼
Threat Analysis
      │
      ├── Dashboard
      └── Telegram Alerts
```

---

## Current Status

This project is currently a prototype developed for learning and demonstrating AI-assisted SOC operations.

---

## License

This project is intended for educational and research purposes.
