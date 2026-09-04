import express from "express";
import path from "path";
import dns from "dns";
import { createServer as createViteServer } from "vite";
import OpenAI from "openai";
import dotenv from "dotenv";
import splunkjs from "splunk-sdk";
import axios from "axios";
import https from "https";

dns.setDefaultResultOrder("ipv4first");

dotenv.config({
    path: "/home/ram/Downloads/soc/.env"
});

console.log("========== ENV DEBUG ==========");
console.log(
    "FEATHERLESS:",
    process.env.FEATHERLESS_API_KEY ? "LOADED" : "MISSING"
);
console.log("TELEGRAM TOKEN:", process.env.TELEGRAM_BOT_TOKEN ? "LOADED" : "MISSING");
console.log("TELEGRAM CHAT:", process.env.TELEGRAM_GROUP_CHAT_ID);
console.log("================================");

// Initialize Express
const app = express();
app.use(express.json({
    limit: "2mb"
}));
const PORT = Number(process.env.PORT) || 3000;

// Initialize featherless AI Client
const ai = new OpenAI({
    apiKey: process.env.FEATHERLESS_API_KEY,
    baseURL: "https://api.featherless.ai/v1",
    defaultHeaders: {
        "HTTP-Referer": "http://localhost:3000",
        "X-Title": "CyberNexsus SOC"
    }
});

const splunkService = new splunkjs.Service({
    scheme: "https",
    host: process.env.SPLUNK_HOST,
port: Number(process.env.SPLUNK_PORT),
username: process.env.SPLUNK_USER,
password: process.env.SPLUNK_PASSWORD,
    version: "10.4.1"
});


// Canonical SOC risk engine.
// The local engine is the single source of truth for score + severity.
// AI never creates or overrides the risk score.

function getSeverityFromRiskScore(
    score: number
): "low" | "medium" | "high" | "critical" {
    const risk = Math.max(
        0,
        Math.min(100, Math.round(Number(score) || 0))
    );

    if (risk >= 75) return "critical";
    if (risk >= 50) return "high";
    if (risk >= 25) return "medium";

    return "low";
}

function calculateRiskScore(logs: any[]): number {
    if (!Array.isArray(logs) || logs.length === 0) {
        return 0;
    }

    let score = 0;

    let failedLogins = 0;
    let successfulLogins = 0;
    let privilegedEvents = 0;
    let suspiciousSysmon = 0;
    let confirmedNetworkAlerts = 0;
    let suspiciousNetworkEvents = 0;

// USB / confidential data monitoring
let usbActivity = 0;
let sensitiveFileActivity = 0;
let potentialDataExfiltration = false;
let hasUsbEvidence = false;

let sshBruteForce = false;
    let portScan = false;

    let hasWindows = false;
    let hasLinux = false;
    let hasNetwork = false;

    for (const log of logs) {
        const raw = String(
            log._raw ??
            log.message ??
            ""
        ).toLowerCase();

        const index = String(
            log.index ??
            ""
        ).toLowerCase();

        const sourcetype = String(
            log.sourcetype ??
            log.source ??
            ""
        ).toLowerCase();

        const detectionType = String(
            log.type ??
            log.detectionType ??
            ""
        ).toUpperCase();

        const eventCode = Number(
            log.EventCode ??
            log.eventCode ??
            log.EventID ??
            0
        );

        // =========================
        // EXPLICIT DETECTIONS
        // =========================

        if (
            detectionType === "SSH_BRUTE_FORCE" ||
            log.sshBruteForce === true
        ) {
            sshBruteForce = true;

            const attempts = Number(
                log.failedAttempts ??
                log.attempts ??
                0
            );

            failedLogins += attempts;
        }

        if (
            detectionType === "PORT_SCAN" ||
            log.portScan === true
        ) {
            portScan = true;
        }

        // =========================
        // WINDOWS
        // =========================

        if (index === "windows-10") {
            hasWindows = true;

            if (eventCode === 4625) {
                failedLogins++;
            }

            if (eventCode === 4624) {
                successfulLogins++;
            }

            if (eventCode === 4672) {
                privilegedEvents++;
            }

            if (
                sourcetype.includes("sysmon") &&
                (
                    raw.includes("powershell") ||
                    raw.includes("cmd.exe") ||
                    raw.includes("encodedcommand") ||
                    raw.includes("mimikatz") ||
                    raw.includes("rundll32") ||
                    raw.includes("regsvr32")
                )
            ) {
                suspiciousSysmon++;
            }
        }
// =========================
// USB / REMOVABLE DEVICE DETECTION
// =========================

// Detect USB/removable device activity from Windows telemetry.
const isUsbEvent =
    eventCode === 6416 ||
    eventCode === 6419 ||
    raw.includes("removable media") ||
    raw.includes("removable disk") ||
    raw.includes("usb storage") ||
    raw.includes("usbstor");

if (isUsbEvent) {
    usbActivity++;
    hasUsbEvidence = true;
}

// =========================
// CONFIDENTIAL FILE ACTIVITY
// =========================

// Detect activity involving files that your organization
// considers sensitive.
const sensitiveKeywords = [
    "confidential",
    "secret",
    "password",
    "financial",
    "customer",
    "database",
    ".pdf",
    ".xlsx",
    ".docx"
];

const isSensitiveFile = sensitiveKeywords.some(keyword =>
    raw.includes(keyword)
);

// Detect possible file copy/write activity.
const isCopyActivity =
    raw.includes("copy") ||
    raw.includes("write") ||
    raw.includes("createfile") ||
    raw.includes("file create");

if (isSensitiveFile && isCopyActivity) {
    sensitiveFileActivity++;
}

// High-confidence correlation:
// sensitive-file activity involving a removable/USB device.
if (
    isSensitiveFile &&
    (
        raw.includes("usb") ||
        raw.includes("removable") ||
        raw.includes("driveletter")
    )
) {
    potentialDataExfiltration = true;
}
        // =========================
        // LINUX / SSH
        // =========================

        if (index === "linux") {
            hasLinux = true;

            if (
                raw.includes("failed password") ||
                raw.includes("authentication failure") ||
                raw.includes("invalid user")
            ) {
                failedLogins++;
            }

            if (
                raw.includes("accepted password") ||
                raw.includes("accepted publickey") ||
                raw.includes("session opened")
            ) {
                successfulLogins++;
            }

            if (raw.includes("sudo")) {
                privilegedEvents++;
            }
        }

        // =========================
        // NETWORK / SURICATA
        // =========================

        if (
            index === "network" ||
            sourcetype.includes("suricata")
        ) {
            hasNetwork = true;

            if (
                raw.includes("severity\":1") ||
                raw.includes("malware") ||
                raw.includes("trojan") ||
                raw.includes("exploit") ||
                raw.includes("command and control") ||
                raw.includes("c2") ||
                raw.includes("brute force")
            ) {
                confirmedNetworkAlerts++;
            }
        }

        // =========================
        // ZEEK
        // =========================

        if (sourcetype.includes("zeek")) {
            hasNetwork = true;

            // Only count explicit scan indicators.
            // Generic "notice" or "suspicious" is NOT enough.
            if (
                raw.includes("port scan") ||
                raw.includes("port_scan") ||
                raw.includes("scan detected") ||
                raw.includes("scanning host")
            ) {
                suspiciousNetworkEvents++;
                portScan = true;
            }
        }
    }

// Automatically detect repeated SSH authentication failures
if (failedLogins >= 5) {
    sshBruteForce = true;
}
    // =========================
    // SSH BRUTE FORCE
    // =========================

    if (sshBruteForce) {
        if (failedLogins >= 20) {
            score += 70;
        } else if (failedLogins >= 10) {
            score += 55;
        } else if (failedLogins >= 5) {
            score += 40;
        } else if (failedLogins > 0) {
            score += 20;
        }
    } else {
        score += Math.min(failedLogins * 5, 25);
    }

    // Successful login after failed authentication
    if (sshBruteForce && successfulLogins > 0) {
        score += 25;
    }

    // =========================
    // PORT SCAN
    // =========================

    if (portScan) {
        score += 35;
    }

    // =========================
    // OTHER SECURITY EVIDENCE
    // =========================

    score += Math.min(privilegedEvents * 5, 10);

    score += Math.min(suspiciousSysmon * 10, 25);

    score += Math.min(confirmedNetworkAlerts * 20, 40);

    score += Math.min(suspiciousNetworkEvents * 10, 20);

// =========================
// USB / DATA EXFILTRATION RISK
// =========================

// USB device activity
score += Math.min(usbActivity * 5, 10);

// Sensitive file activity
score += Math.min(sensitiveFileActivity * 10, 20);

// Sensitive data potentially copied to USB/removable storage
if (potentialDataExfiltration) {
    score += 50;
}
    // =========================
    // CORRELATION BONUS
    // =========================

    const sourceCount =
        Number(hasWindows) +
        Number(hasLinux) +
        Number(hasNetwork);

    let evidenceTypes = 0;

    if (sshBruteForce) evidenceTypes++;
    if (portScan) evidenceTypes++;
    if (suspiciousSysmon > 0) evidenceTypes++;
    if (confirmedNetworkAlerts > 0) evidenceTypes++;
    if (privilegedEvents > 0) evidenceTypes++;
    if (successfulLogins > 0) evidenceTypes++;

    if (sourceCount >= 2 && evidenceTypes >= 2) {
        score += 10;
    }

    // Brute force + successful login is particularly important
    if (sshBruteForce && successfulLogins > 0) {
        score += 10;
    }

    const finalScore = Math.min(
        100,
        Math.max(0, Math.round(score))
    );

    console.log("========== RISK DEBUG ==========");
    console.log("Total logs:", logs.length);
    console.log("Failed logins:", failedLogins);
    console.log("Successful logins:", successfulLogins);
    console.log("SSH brute force:", sshBruteForce);
    console.log("Port scan:", portScan);
    console.log("Privileged events:", privilegedEvents);
    console.log("Suspicious Sysmon:", suspiciousSysmon);
    console.log("Confirmed network alerts:", confirmedNetworkAlerts);
    console.log("Suspicious network events:", suspiciousNetworkEvents);
    console.log("Evidence types:", evidenceTypes);
    console.log("Final risk score:", finalScore);
    console.log("================================");

    return finalScore;
}
    
 

async function runSplunkSearch(search: string): Promise<any[]> {
    const response = await axios.post(
        "https://localhost:8089/services/search/jobs/export",
        new URLSearchParams({ search, output_mode: "json" }),
        {
            auth: {
                username: process.env.SPLUNK_USER,
                password: process.env.SPLUNK_PASSWORD,
            },
            httpsAgent: new https.Agent({ rejectUnauthorized: false }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            responseType: "text",
            timeout: 15000,
        }
    );

    if (!response.data?.trim()) return [];
    return response.data.trim().split("\n").filter(Boolean).map((line: string) => JSON.parse(line));
}

// Dashboard data: small and recent. It is NOT used as the alert trigger.
async function fetchSplunkLogs(): Promise<any[]> {
    return runSplunkSearch(`
search (index=windows-10 OR index=linux OR index=network) earliest=-15m latest=now
| eval category=case(index=="windows-10","windows", index=="linux","linux", index=="network","network")
| table _time host category index sourcetype EventCode _raw
| sort -_time
| head 50
`);
}

// Alert data: strong security evidence from the last 5 minutes.
async function fetchSplunkSecurityEvents(): Promise<any[]> {
    return runSplunkSearch(`
search (index=windows-10 OR index=linux OR index=network) earliest=-5m latest=now
| eval category=case(
    index=="windows-10","windows",
    index=="linux","linux",
    index=="network","network"
)
| where EventCode=4625
    OR EventCode=4672
    OR like(lower(_raw),"%failed password%")
    OR like(lower(_raw),"%accepted password%")
    OR like(lower(_raw),"%accepted publickey%")
    OR like(lower(_raw),"%session opened%")
    OR like(lower(_raw),"%authentication failure%")
    OR like(lower(_raw),"%invalid user%")
    OR like(lower(_raw),"%encodedcommand%")
    OR like(lower(_raw),"%mimikatz%")
    OR like(lower(_raw),"%rundll32%")
    OR like(lower(_raw),"%regsvr32%")
    OR like(lower(_raw),"%suricata%")
    OR like(lower(_raw),"%port scan%")
    OR like(lower(_raw),"%network scan%")
    OR like(lower(_raw),"%brute force%")
| table _time host category index sourcetype EventCode _raw src_ip dest_ip dest_port
| sort -_time
| head 50
`);
}

// Telegram Alert Function

async function sendTelegramAlert(message: string) {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_GROUP_CHAT_ID;

    if (!botToken || !chatId) {
        console.log("Telegram token or chat id missing");
        return;
    }

    try {
        await axios.post(
            `https://api.telegram.org/bot${botToken}/sendMessage`,
            { chat_id: chatId, text: message, parse_mode: "HTML" },
            { timeout: 10000, family: 4 }
        );
        console.log("Telegram alert sent successfully");
    } catch (error: any) {
        console.log("Telegram error:", error.response?.data || error.message);
    }
}

let monitoringInProgress = false;
let lastAlertFingerprint = "";
let lastAlertTime = 0;
const ALERT_COOLDOWN_MS = 15 * 60 * 1000;

function makeFingerprint(logs: any[]): string {
    return JSON.stringify(logs.map(l => ({
        host: l.host,
        index: l.index,
        eventCode: l.EventCode,
        src_ip: l.src_ip,
        attack_type: l.attack_type,
        message: String(l._raw ?? l.message ?? "").slice(0, 160)
    })));
}

function normalizeSecurityLog(item: any): any {
    const r = item?.result ?? item ?? {};

    const detectionType = String(
        r.type ??
        r.detectionType ??
        r.attack_type ??
        ""
    ).toUpperCase();

    const failedAttempts = Number(
        r.failedAttempts ??
        r.failed_attempts ??
        r.attempts ??
        r.count ??
        0
    );

    return {
        timestamp: r._time ?? r.timestamp ?? new Date().toISOString(),

        host:
            r.host ??
            r.target ??
            r.dest_host ??
            "unknown",

        source:
            r.sourcetype ??
            r.source ??
            r.index ??
            "",

        category:
            r.category ??
            r.index ??
            "",

        severity:
            r.severity ??
            "high",

        message: String(
            r._raw ??
            r.message ??
            r.description ??
            `${detectionType} detection`
        ).slice(0, 600),

        _raw: String(
            r._raw ??
            r.message ??
            ""
        ),

        index: r.index,

        EventCode:
            r.EventCode ??
            r.eventCode ??
            r.EventID,

        src_ip:
            r.src_ip ??
            r.sourceIp ??
            r.srcIp,

        dest_ip:
    r.dest_ip ??
    r.targetIp ??
    r.destinationIp ??
    r.target,

dest_port:
    r.dest_port ??
    r.targetPort ??
    r.destinationPort ??
    r.dest_port,

        attack_type:
            r.attack_type ??
            detectionType,

        type: detectionType,

        detectionType: detectionType,

        failedAttempts: failedAttempts,

        attempts: failedAttempts,

        scanCount: Number(
            r.scanCount ??
            r.scan_count ??
            0
        ),

        sshBruteForce:
            detectionType === "SSH_BRUTE_FORCE" ||
            r.sshBruteForce === true,

        portScan:
            detectionType === "PORT_SCAN" ||
            r.portScan === true
    };
}

async function investigateAndAlert(
    logs: any[],
    riskScore?: number,
    forceInvestigation = false
) {
    if (!logs.length) return null;

    const canonicalRiskScore = riskScore ?? calculateRiskScore(logs);
    const canonicalSeverity = getSeverityFromRiskScore(canonicalRiskScore);

    // Automatic monitoring investigates only higher-risk events.
// Manual investigation can explicitly bypass this threshold.
if (canonicalRiskScore < 50 && !forceInvestigation) {
    console.log(`Risk ${canonicalRiskScore}: below automatic AI/Telegram threshold.`);
    return null;
}

    const fingerprint = makeFingerprint(logs);
    const now = Date.now();
    if (fingerprint === lastAlertFingerprint && now - lastAlertTime < ALERT_COOLDOWN_MS) {
        console.log("Duplicate incident suppressed.");
        return null;
    }

    const compactLogs = logs.slice(0, 8).map(normalizeSecurityLog);

    if (!process.env.FEATHERLESS_API_KEY) {
        const report = {
            title: "Security Detection",
            summary: "A security rule crossed the investigation threshold.",
            riskScore: canonicalRiskScore,
            severity: canonicalSeverity,
            timeline: compactLogs.map(l => ({ time: l.timestamp, event: l.message, host: l.host })),
            mitreMapping: [],
            technicalDetails: "AI is not configured. Review the correlated SIEM evidence manually.",
            remediationSteps: [
                "Validate the source and destination hosts in Splunk.",
                "Review authentication and process telemetry around the detection window.",
                "Contain the source only after confirming the activity is unauthorized."
            ]
        };
        if (canonicalSeverity === "high" || canonicalSeverity === "critical") {
            await sendTelegramAlert(formatTelegramAlert(report));
            lastAlertFingerprint = fingerprint;
            lastAlertTime = now;
        }
        return report;
    }

    const formattedLogsText = compactLogs.map(l => `
Host: ${l.host}
Source: ${l.source}
Category: ${l.category}
Time: ${l.timestamp}
Event: ${l.message}
`).join("\n---\n");

    const response = await ai.chat.completions.create({
        model: "Qwen/Qwen2.5-7B-Instruct",
        messages: [
            {
                role: "system",
                content: `You are a SOC incident analyst. Use ONLY the supplied evidence.
Do not invent CVEs, IP reputation, successful compromise, exfiltration, or MITRE techniques.
Normal DNS, TLS, TCP, or UDP connections alone are not proof of malicious activity.
Recommend defensive, evidence-based actions. The local risk score is authoritative.`
            },
            {
                role: "user",
                content: `Investigate these correlated SIEM events.
Authoritative local risk score: ${canonicalRiskScore}/100 (${canonicalSeverity}).

${formattedLogsText}

Return ONLY JSON with:
{
  "title":"",
  "summary":"",
  "riskScore":0,
  "severity":"",
  "timeline":[{"time":"","event":"","host":""}],
  "mitreMapping":[{"techniqueId":"","techniqueName":"","tactic":""}],
  "technicalDetails":"",
  "remediationSteps":["", "", ""]
}
If the evidence does not support a technique, leave mitreMapping empty.`
            }
        ],
        temperature: 0.1,
        max_tokens: 1500
    });

    console.log("========== FULL AI RESPONSE ==========");
console.dir(response, { depth: null });
console.log("======================================");

const text = response.choices?.[0]?.message?.content;

if (!text) {
    throw new Error(
        `Empty AI response. Finish reason: ${
            response.choices?.[0]?.finish_reason || "unknown"
        }`
    );
}
    const reportJson = JSON.parse(text.replace(/```json/g, "").replace(/```/g, "").trim());

    reportJson.riskScore = canonicalRiskScore;
    reportJson.severity = canonicalSeverity;
    reportJson.remediationSteps = Array.isArray(reportJson.remediationSteps)
        ? reportJson.remediationSteps.slice(0, 5)
        : [];
    reportJson.mitreMapping = Array.isArray(reportJson.mitreMapping)
        ? reportJson.mitreMapping.slice(0, 5)
        : [];

    if (canonicalSeverity === "high" || canonicalSeverity === "critical") {
        await sendTelegramAlert(formatTelegramAlert(reportJson));
        lastAlertFingerprint = fingerprint;
        lastAlertTime = now;
    }

    return reportJson;
}

function formatTelegramAlert(report: any): string {
    const hosts = [...new Set((report.timeline || []).map((x: any) => x.host).filter(Boolean))].join(", ");
    const mitre = (report.mitreMapping || []).map((m: any) => `${m.techniqueId} - ${m.techniqueName}`).join("\n") || "Not established from available evidence";
    const actions = (report.remediationSteps || []).map((x: string) => `• ${x}`).join("\n") || "Review the incident in Splunk.";
    return `🚨 <b>CyberNexsus Security Alert</b>\n\n<b>Severity:</b> ${report.severity.toUpperCase()}\n<b>Risk Score:</b> ${report.riskScore}/100\n\n<b>Incident:</b> ${report.title}\n\n<b>Summary:</b> ${report.summary}\n\n<b>Affected Hosts:</b> ${hosts || "Unknown"}\n\n<b>MITRE:</b> ${mitre}\n\n<b>AI Recommended Actions:</b>\n${actions}`;
}

async function monitorSplunk() {
    if (monitoringInProgress) {
        console.log("Monitor already running; skipping cycle.");
        return;
    }
    monitoringInProgress = true;
    try {
        console.log("========== SPLUNK MONITOR ==========");
        const events = (await fetchSplunkSecurityEvents()).map(normalizeSecurityLog);
        if (!events.length) {
            console.log("No new security events in last 5 minutes.");
            return;
        }
        const score = calculateRiskScore(events);
        console.log("Canonical SOC Risk Score:", score);
        await investigateAndAlert(events, score);
    } catch (error: any) {
        console.log("SPLUNK MONITOR ERROR:", error.message);
    } finally {
        monitoringInProgress = false;
    }
}

// Manual Telegram test. Uses a fixed test message and never prints secrets.
app.get("/api/test/telegram", async (req, res) => {
    await sendTelegramAlert("🚨 CyberNexsus test alert\n\nTelegram integration is working.");
    res.json({ message: "Test alert sent" });
});

// Real-time Splunk webhook.
// Configure a Splunk alert action to POST its detection result here.
app.post("/api/alerts/splunk", async (req, res) => {
    const configuredSecret = process.env.SPLUNK_WEBHOOK_SECRET;
    const suppliedSecret = String(req.query.token ?? req.headers["x-cybernexsus-secret"] ?? "");
    if (configuredSecret && suppliedSecret !== configuredSecret) {
        return res.status(401).json({ error: "Unauthorized webhook" });
    }

    try {
        const body = req.body ?? {};
        const rawEvents = Array.isArray(body.results)
            ? body.results
            : Array.isArray(body.logs)
                ? body.logs
                : [body.result ?? body];
        const events = rawEvents.filter(Boolean).map(normalizeSecurityLog);
        const score = calculateRiskScore(events);
        const report = await investigateAndAlert(events, score);
        console.log(`Real-time webhook processed: ${events.length} event(s), risk=${score}`);
        return res.json({ ok: true, riskScore: score, severity: getSeverityFromRiskScore(score), report });
    } catch (error: any) {
        console.error("Splunk webhook error:", error.message);
        return res.status(500).json({ error: "Webhook processing failed" });
    }
});

// Setup Vite Dev server / static file serving
app.get("/api/splunk/test", async (req, res) => {
console.log("========== HIT /api/splunk/test ==========");
    try {
        await splunkService.login();

        res.json({
            success: true,
            message: "Splunk connection successful"
        });

    } catch (err: any) {
        console.error(err);

        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});

// Fetch latest logs from Splunk
app.get("/api/splunk/logs", async (req, res) => {
    try {
        const rawLogs = await fetchSplunkLogs();
        const riskScore = calculateRiskScore(
            rawLogs.map((item:any) => item.result)
        );

        // Keep the original array shape for compatibility while exposing
        // the canonical score in a response header.
        res.setHeader("X-SOC-Risk-Score", String(riskScore));
        res.json(rawLogs);
    } catch (err: any) {
        console.error("Splunk Error:", err);

        res.status(500).json({
            error: err.message,
        });
    }
});

// Fetch log volume statistics
app.get("/api/splunk/stats", async (req, res) => {

    try {

        const response = await axios.post(
            "https://localhost:8089/services/search/jobs/export",

            new URLSearchParams({

                search: `
| tstats count where index=* by index
| search index=windows-10 OR index=linux OR index=network
`,

                output_mode: "json",

            }),

            {
                auth: {
    username: process.env.SPLUNK_USER,
    password: process.env.SPLUNK_PASSWORD,
},

                httpsAgent: new https.Agent({
                    rejectUnauthorized:false,
                }),

                headers:{
                    "Content-Type":"application/x-www-form-urlencoded",
                },

                responseType:"text",
            }
        );


        const stats = response.data
            .trim()
            .split("\n")
            .map((line:string)=>JSON.parse(line));


        const result = stats.map((item:any)=>({

            category:
                item.result.index === "windows-10"
                ? "Windows"
                :
                item.result.index === "linux"
                ? "Linux"
                :
                item.result.index === "network"
                ? "Network"
                :
                item.result.index,

            count:Number(item.result.count)

        }));


        res.json(result);


    } catch(err:any){

        console.error("Stats Error:",err);

        res.status(500).json({
            error:err.message
        });

    }

});

// API: Analyze security events
app.post("/api/threats/analyze", async (req, res) => {
    const { logs, riskScore: requestedRiskScore } = req.body;
    if (!Array.isArray(logs) || logs.length === 0) {
        return res.status(400).json({ error: "Missing or invalid logs array." });
    }

    try {
        const normalized = logs.map(normalizeSecurityLog);
        const score = Number.isFinite(Number(requestedRiskScore))
            ? Math.min(100, Math.max(0, Math.round(Number(requestedRiskScore))))
            : calculateRiskScore(normalized);
        console.log(`Manual AI investigation requested. Risk score: ${score}/100`);

const report = await investigateAndAlert(
    normalized,
    score,
    true
);

        if (report) return res.json(report);
        return res.json({
            title: "No escalation required",
            summary: "The supplied events did not cross the investigation threshold.",
            riskScore: score,
            severity: getSeverityFromRiskScore(score),
            timeline: normalized.slice(0, 10).map(l => ({ time: l.timestamp, event: l.message, host: l.host })),
            mitreMapping: [],
            technicalDetails: "No AI investigation was triggered because the local detection engine did not reach the configured threshold.",
            remediationSteps: []
        });
    } catch (err: any) {
        console.error("Threat analysis error:", err.message);
        return res.status(500).json({ error: `Internal security analysis error: ${err.message || err}` });
    }
});

// Setup Vite Dev server / static file serving
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    console.log("Starting server in DEVELOPMENT mode with Vite dev middleware...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("Starting server in PRODUCTION mode...");
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Threat Sentinel backend running on http://0.0.0.0:${PORT}`);
  });
}
// Setup Vite Dev server / static file serving
// ========================================
// NORMAL USER MODE
// ========================================

interface UserSecurityAnalysis {
    riskScore: number;
    severity: "low" | "medium" | "high";
    indicators: string[];
    urls: string[];
}

function analyzeUserContent(text: string): UserSecurityAnalysis {

    const indicators: string[] = [];

    // Extract URLs
    const urls = text.match(/https?:\/\/[^\s]+/gi) || [];

    let riskScore = 0;

    const lowerText = text.toLowerCase();

    const suspiciousPatterns = [

        {
            words: ["urgent", "immediately", "act now"],
            score: 10,
            reason: "Urgency language detected"
        },

        {
            words: ["otp", "one time password"],
            score: 15,
            reason: "Requests sensitive authentication information"
        },

        {
            words: ["password", "login credentials"],
            score: 15,
            reason: "Requests sensitive credentials"
        },

        {
            words: ["account suspended", "account blocked"],
            score: 15,
            reason: "Account threat or suspension claim detected"
        },

        {
            words: ["click here", "verify now"],
            score: 10,
            reason: "Requests immediate link interaction"
        },

        {
            words: ["prize", "winner", "reward"],
            score: 8,
            reason: "Unexpected reward or prize language detected"
        },

        {
            words: ["bank account", "payment required"],
            score: 10,
            reason: "Financial or payment-related language detected"
        }

    ];

    for (const pattern of suspiciousPatterns) {

        if (
            pattern.words.some(
                word => lowerText.includes(word)
            )
        ) {

            indicators.push(pattern.reason);

            riskScore += pattern.score;
        }
    }

    if (urls.length > 0) {

        indicators.push(
            `Contains ${urls.length} external URL(s)`
        );

        riskScore += 15;
    }

    riskScore = Math.min(riskScore, 100);

    const severity =
        riskScore >= 70
            ? "high"
            : riskScore >= 40
                ? "medium"
                : "low";

    return {
        riskScore,
        severity,
        indicators,
        urls
    };
}


// ========================================
// NORMAL USER ANALYSIS API
// ========================================

app.post("/api/user/analyze", async (req, res) => {

    try {

        const text = String(
            req.body?.text || ""
        ).trim();

        if (!text) {

            return res.status(400).json({
                error: "Please provide text to analyze"
            });
        }

        if (text.length > 10000) {

            return res.status(400).json({
                error: "Text is too long"
            });
        }

        const analysis = analyzeUserContent(text);

        return res.json({

            mode: "normal-user",

            analysis

        });

    } catch (error: any) {

        console.error(
            "User Mode analysis error:",
            error.message
        );

        return res.status(500).json({
            error: "User analysis failed"
        });
    }
});

startServer();

// Automatic Splunk monitoring
if (process.env.ENABLE_SPLUNK_POLLING === "true") {

    console.log("Splunk monitoring enabled: checking every 10 seconds");

    // Run immediately when the server starts
    void monitorSplunk();

    // Check Splunk every 10 seconds
    setInterval(() => {
        void monitorSplunk();
    }, 10000);

} else {
    console.log("Event-driven mode enabled: waiting for Splunk webhook detections.");
}
