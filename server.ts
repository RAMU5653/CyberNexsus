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
console.log("OPENROUTER:", process.env.OPENROUTER_API_KEY ? "LOADED" : "MISSING");
console.log("TELEGRAM TOKEN:", process.env.TELEGRAM_BOT_TOKEN ? "LOADED" : "MISSING");
console.log("TELEGRAM CHAT:", process.env.TELEGRAM_GROUP_CHAT_ID);
console.log("================================");

// Initialize Express
const app = express();
app.use(express.json({
    limit: "50mb"
}));
const PORT = 3000;

// Initialize OpenRouter AI Client
const ai = new OpenAI({
  apiKey: process.env.OPENROUTER_API_KEY,
  baseURL: "https://openrouter.ai/api/v1",
  defaultHeaders: {
    "HTTP-Referer": "http://localhost:3000",
    "X-Title": "Cyber-Nexsus-SOC"
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

// Telegram Alert Function

async function sendTelegramAlert(message:string){

    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_GROUP_CHAT_ID;


    console.log("========== TELEGRAM DEBUG ==========");
    console.log("BOT TOKEN:", botToken);
    console.log("CHAT ID:", chatId);


    if(!botToken || !chatId){
        console.log("Telegram token or chat id missing");
        return;
    }


    try {

        const response = await axios.post(
    `https://api.telegram.org/bot${botToken}/sendMessage`,
    {
        chat_id: chatId,
        text: message,
        parse_mode:"HTML"
    },
    {
        timeout: 15000,
        family: 4
    }
);


        console.log("Telegram API Response:");
        console.log(response.data);

        console.log("Telegram alert sent successfully");


    } catch(error:any){

    console.log("========== TELEGRAM ERROR ==========");

    if(error.response){
        console.log("Status:", error.response.status);
        console.log("Data:", error.response.data);
    }
    else if(error.request){
        console.log("No response received from Telegram");
        console.log(error.request);
    }
    else{
        console.log("Error:", error.message);
    }

    console.log("====================================");

}

}

async function monitorSplunk(){

    try {

        console.log("========== SPLUNK MONITOR ==========");


        const response = await axios.post(

            "https://localhost:8089/services/search/jobs/export",

            new URLSearchParams({

                search: `
search (index=windows-10 OR index=linux OR index=network)

| eval severity=case(

EventCode=4625,"high",

EventCode=1,"high",

index="linux" AND like(_raw,"%Failed password%"),"high",

index="network" AND like(_raw,"%alert%"),"critical",

true(),"low"

)

| where severity="high" OR severity="critical"

| table _time host index sourcetype EventCode severity _raw

| sort -_time

| head 10
`,

                output_mode:"json"

            }),


            {

                auth: {
    username: process.env.SPLUNK_USER,
    password: process.env.SPLUNK_PASSWORD
},


                httpsAgent:new https.Agent({

                    rejectUnauthorized:false

                }),


                headers:{

                    "Content-Type":"application/x-www-form-urlencoded"

                },


                responseType:"text"

            }

        );



        const logs=response.data
        .trim()
        .split("\n")
        .map((line:string)=>JSON.parse(line));


        console.log("Detected Security Events:",logs.length);



        if(logs.length===0){

            console.log("No high severity events found");

            return;

        }



        console.log(logs);



        // Send logs to AI Analyzer

        const aiResponse = await axios.post(

            "http://localhost:3000/api/threats/analyze",

            {

                logs: logs.map((item:any)=>({

                    host:item.result.host,

                    source:item.result.sourcetype,

                    severity:item.result.severity,

                    category:item.result.index,

                    message:item.result._raw

                }))

            }

        );



        console.log("========== AI ANALYSIS ==========");

        console.log(aiResponse.data);



        const report=aiResponse.data;



        // Telegram alert for HIGH / CRITICAL

        if(

            report.severity?.toLowerCase()=="high" ||

            report.severity?.toLowerCase()=="critical"

        ){


            const message=`

🚨 <b>CyberNexsus SOC Alert</b>


<b>Severity:</b>
${report.severity}


<b>Risk Score:</b>
${report.riskScore}/100


<b>Incident:</b>
${report.title}


<b>Summary:</b>
${report.summary}


<b>Host:</b>
${report.timeline
.map((x:any)=>x.host)
.join(", ")}


<b>MITRE:</b>
${report.mitreMapping
.map((m:any)=>m.techniqueId+" - "+m.techniqueName)
.join("\n")}


<b>Actions:</b>

${report.remediationSteps
.map((x:string)=>"• "+x)
.join("\n")}

`;



            await sendTelegramAlert(message);


            console.log("Telegram alert sent");

        }


    }


    catch(error:any){


        console.log("========== SPLUNK MONITOR ERROR ==========");

        console.log(error.message);


    }

}

//test telegram 
app.get("/api/test/telegram", async(req,res)=>{

    await sendTelegramAlert(
`
🚨 Test Alert

CyberNexsus Telegram integration working.

Severity: HIGH
Risk Score: 95
`
    );

    res.json({
        message:"Test alert sent"
    });

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
        const response = await axios.post(
            "https://localhost:8089/services/search/jobs/export",
            new URLSearchParams({
                search: `
search (index=windows-10 OR index=linux OR index=network)
| eval category=case(
    index=="windows-10","windows",
    index=="linux","linux",
    index=="network","network"
)
| table _time host category sourcetype _raw
| sort -_time
| head 100
`,
                output_mode: "json",
            }),
            {
                auth: {
    username: process.env.SPLUNK_USER,
    password: process.env.SPLUNK_PASSWORD,
},
                httpsAgent: new https.Agent({
                    rejectUnauthorized: false,
                }),
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                responseType: "text",
            }
        );

        const logs = response.data
            .trim()
            .split("\n")
            .map((line: string) => JSON.parse(line));

        res.json(logs);

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
  const { logs } = req.body;

  if (!logs || !Array.isArray(logs) || logs.length === 0) {
    return res.status(400).json({ error: "Missing or invalid logs array." });
  }

  // Check if AI is configured; if not, return a highly realistic simulation
  if (!process.env.OPENROUTER_API_KEY) {
    console.log("No OpenRouter API key available; returning simulation analysis.");
    return res.json({
      title: "Correlated Security Incident - Fallback Simulation Mode",
      summary: "This report was generated in offline/fallback simulation mode because no OPENROUTER_API_KEY was configured in Settings > Secrets. In production, this completes a live, multi-variable correlation of host and network telemetry using OpenRouter AI models.",
      riskScore: Math.min(100, logs.reduce((acc, curr) => acc + (curr.details?.riskScoreContribution || 5), 30)),
      severity: logs.some(l => l.severity === "critical") ? "critical" : logs.some(l => l.severity === "high") ? "high" : "medium",
      timeline: logs.map(l => ({
        time: l.timestamp || "10:45:00",
        event: l.message,
        host: l.host
      })),
      mitreMapping: logs.filter(l => l.mitreId).map(l => ({
        techniqueId: l.mitreId!,
        techniqueName: l.mitreName || "Unknown Technique",
        tactic: l.category || "Defense Evasion"
      })),
      technicalDetails: `LOG DUMP CORRELATION ANALYZER (OFFLINE):\n` + logs.map(l => `[${l.host} - ${l.source}] (${l.severity.toUpperCase()}): ${l.message}`).join("\n\n") + `\n\nRECOMMENDATION: Configure a real OpenRouter API Key to activate live AI threat analysis.`,
      remediationSteps: [
        "Isolate affected VMs (Windows-VM and/or Kali-VM) from the network to stop active exfiltration channels.",
        "Terminate processes identified as malicious (e.g. powershell.exe executing IEX scripts, or rogue binaries).",
        "Perform credential rotation for compromised accounts (e.g., Administrator or root user keys).",
        "Audit firewall rules on Suricata and index patterns in Splunk for anomalous outbound indicators."
      ]
    });
  }

  try {

    // Remove useless huge logs and keep only security-relevant data
    const cleanedLogs = logs
        .filter((l:any) => {

            const raw = l.message || l._raw || "";

            // Ignore Suricata statistics logs
            if (raw.includes('"event_type":"stats"')) {
                return false;
            }

            return true;

        })
        .slice(0,10)
        .map((l:any) => ({

            timestamp: l.timestamp || l._time,
            host: l.host,
            source: l.source,
            severity: l.severity || "low",

            // Keep only first 1000 characters
            message: (
                l.message ||
                l._raw ||
                ""
            ).substring(0,1000),

            category: l.category || l.index

        }));


    const formattedLogsText = cleanedLogs.map(l => (

`
Host: ${l.host}
Source: ${l.source}
Severity: ${l.severity}
Time: ${l.timestamp}
Category: ${l.category}

Event:
${l.message}

-------------------
`

    )).join("\n");

    const prompt = `Perform an elite Tier-3 security incident investigation on the following forwarded SIEM log events. Cross-correlate them to detect multi-stage attack vectors (e.g., reconnaisance leading to brute force, command execution, and eventual exfiltration or impact).

Log events to investigate:
${formattedLogsText}

Analyze this data and respond with a structured JSON analysis conforming exactly to the requested schema. Ensure the composite riskScore is accurately calculated (0-100) based on severity. Make your technicalDetails highly detailed and cybersecurity-oriented (referencing CVEs, real-world techniques, and Splunk index correlation details where applicable). Provide 3-5 concrete actionable remediation steps.`;

    const response = await ai.chat.completions.create({

  model: "meta-llama/llama-3.3-70b-instruct",

  messages: [
    {
      role: "system",
      content:
      `You are an elite Tier-3 Cyber Security Incident Handler,
      SIEM correlation engineer, and MITRE ATT&CK specialist.

      Analyze:
      - Windows Sysmon logs
      - Windows Event Logs
      - Linux auth.log
      - Zeek network logs
      - Suricata alerts

      Provide accurate incident investigation.`
    },

    {
      role: "user",
      content:
      `${prompt}

Return ONLY valid JSON in this format:

{
"title": "",
"summary": "",
"riskScore": 0,
"severity": "",
"timeline": [
  {
    "time": "",
    "event": "",
    "host": ""
  }
],
"mitreMapping": [
  {
    "techniqueId": "",
    "techniqueName": "",
    "tactic": ""
  }
],
"technicalDetails": "",
"remediationSteps": [
  ""
]
}`
    }
  ],

  temperature: 0.2
});

    const text = response.choices[0].message.content;

if (!text) {
  throw new Error("Empty response received from OpenRouter API");
}

console.log("========== RAW AI RESPONSE ==========");
console.log(text);
console.log("=====================================");

const cleanJson = text
.replace(/```json/g, "")
.replace(/```/g, "")
.trim();

const reportJson = JSON.parse(cleanJson);

console.log("========== AI REPORT ==========");
console.log("Risk Score:", reportJson.riskScore);
console.log("Severity :", reportJson.severity);
console.log("Title    :", reportJson.title);
console.log("===============================");

// Telegram Alert Trigger

if (
    reportJson.severity?.toLowerCase() === "high" ||
    reportJson.severity?.toLowerCase() === "critical"
) {

    console.log("✅ Telegram alert condition matched.");
    console.log("Severity:", reportJson.severity);
    console.log("Risk Score:", reportJson.riskScore);

    const alertMessage = `

🚨 <b>CyberNexsus AI Security Alert</b>

<b>Severity:</b> ${reportJson.severity.toUpperCase()}

<b>Risk Score:</b> ${reportJson.riskScore}/100

<b>Incident:</b>
${reportJson.title}

<b>Summary:</b>
${reportJson.summary}

<b>Affected Hosts:</b>
${[
    ...new Set(
        reportJson.timeline.map((event:any) => event.host)
    )
].join(", ")}

<b>MITRE Techniques:</b>
${reportJson.mitreMapping
    .map((m:any)=>`${m.techniqueId} - ${m.techniqueName}`)
    .join("\n")}

<b>AI Recommended Actions:</b>
${reportJson.remediationSteps
    .map((step:string)=>"• " + step)
    .join("\n")}

`;

    console.log("Sending Telegram alert...");
    await sendTelegramAlert(alertMessage);
    console.log("Telegram function completed.");

}

return res.json(reportJson);

  } catch (err: any) {
    console.error("OpenRouter analysis error:", err);
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

startServer();


setInterval(()=>{

    monitorSplunk();

},1800000);
