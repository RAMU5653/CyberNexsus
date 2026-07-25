import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield,
  ShieldAlert,
  Terminal,
  Layers,
  Cpu,
  Network,
  Radio,
  Play,
  Pause,
  Sparkles,
  HelpCircle,
  Activity,
  Clock,
  Flame,
  BookOpen,
  Bell,
  RefreshCw,
  Plus,
  ArrowRight,
  TrendingUp,
  Skull,
  CheckCircle,
  AlertCircle
} from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, BarChart, Bar, Cell } from "recharts";

import { LogEvent, MITRETechnique, SimulationScenario, IncidentReport } from "./types";
import { initialLogs, scenarios, getInitialMitreMatrix } from "./data/mockLogs";

import MitreMatrix from "./components/MitreMatrix";
import ThreatTimeline from "./components/ThreatTimeline";
import SplunkGuide from "./components/SplunkGuide";
import AIReportView from "./components/AIReportView";
import { getLiveLogs } from "./services/splunk";

export default function App() {
  // Tabs: "monitor" | "guide"
  const [activeTab, setActiveTab] = useState<"monitor" | "guide">("monitor");

  // Core logs & stream state
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [isStreaming, setIsStreaming] = useState(true);
  const [selectedLogIds, setSelectedLogIds] = useState<string[]>([]);
  const [riskScore, setRiskScore] = useState(0);

  // MITRE state
  const [mitreTechniques, setMitreTechniques] = useState<MITRETechnique[]>(getInitialMitreMatrix());
  const [selectedMitreTech, setSelectedMitreTech] = useState<MITRETechnique | null>(null);

  // AI Investigation state
  const [aiReport, setAiReport] = useState<IncidentReport | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Active Simulation state
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);
  const [simulationStep, setSimulationStep] = useState(0);
  const [simulationLogsInjected, setSimulationLogsInjected] = useState<string[]>([]);

  // Clock
  const [currentTime, setCurrentTime] = useState("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toLocaleTimeString("en-US", { hour12: false }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

useEffect(() => {
  const loadLogs = async () => {
    try {
      const liveLogs = await getLiveLogs();
      setLogs(liveLogs);
    } catch (err) {
      console.error("Failed to load Splunk logs:", err);
    }
  };

  loadLogs();

  const interval = setInterval(loadLogs, 5000);

  return () => clearInterval(interval);
}, []);

//add this code below
useEffect(() => {
  const data = getTimelineChartData();

  setTimelineData(prev => [
    ...prev,
    data[0]
  ].slice(-20));

}, [logs]);

  // Sync MITRE triggered techniques based on present logs
  useEffect(() => {
    const nextMatrix = getInitialMitreMatrix().map(tech => {
      const associated = logs.filter(l => l.mitreId === tech.id);
      return {
        ...tech,
        triggered: associated.length > 0,
        associatedLogsCount: associated.length
      };
    });
    setMitreTechniques(nextMatrix);

    // Sync overall environment risk score based on high severity logs
    // Professional SOC Risk Engine

let windowsRisk = 0;
let linuxRisk = 0;
let networkRisk = 0;

let correlationBonus = 0;


logs.forEach(log => {

  const sourcetype = (log.sourcetype || "").toLowerCase();

  const message = JSON.stringify(log).toLowerCase();


  // ======================
  // Windows Risk
  // ======================

  if(
    sourcetype.includes("wineventlog") ||
    sourcetype.includes("xmlwineventlog") ||
    sourcetype.includes("sysmon") ||
    log.index === "windows-10"
  ){

    const eventCode = Number(
      log.eventCode ||
      log.EventCode ||
      log.EventID ||
      log.event_id
    );


    // Failed Login
    if(eventCode === 4625){
      windowsRisk += 15;
    }


    // Privilege escalation
    if(eventCode === 4672){
      windowsRisk += 25;
    }


    // Sysmon detection
    if(
      sourcetype.includes("sysmon") ||
      message.includes("sysmon")
    ){
      windowsRisk += 10;
    }

  }



  // ======================
  // Kali Linux Risk
  // ======================

  if(
    log.index === "linux" ||
    sourcetype.includes("syslog") ||
    sourcetype.includes("auth")
  ){

    if(message.includes("failed password")){
      linuxRisk += 5;
    }


    if(message.includes("sudo")){
      linuxRisk += 10;
    }

  }




  // ======================
  // Network Risk
  // ======================


  if(
    sourcetype.includes("suricata") ||
    message.includes("suricata")
  ){

    if(message.includes("alert")){
      networkRisk += 30;
    }
    else{
      networkRisk += 15;
    }

  }



  if(
    sourcetype.includes("zeek") ||
    message.includes("conn_state") ||
    message.includes("orig_bytes")
  ){

    networkRisk += 15;

  }


});




// ======================
// Correlation Bonus
// ======================

if(
 windowsRisk > 20 &&
 linuxRisk > 20 &&
 networkRisk > 20
){

 correlationBonus = 25;

}



const totalLogs = logs.length || 1;

let finalRisk =
(
(windowsRisk / totalLogs) +
(linuxRisk / totalLogs) +
(networkRisk / totalLogs) +
correlationBonus
);



finalRisk = Math.min(
100,
Math.round(finalRisk)
);



console.log(
"SOC Risk Debug:",
{
windowsRisk,
linuxRisk,
networkRisk,
correlationBonus,
finalRisk
}
);



setRiskScore(finalRisk);
}, [logs]);
 
  // Simulation execution handler loop
  useEffect(() => {
    if (!activeSimulation) return;

    const scenario = scenarios.find(s => s.id === activeSimulation);
    if (!scenario) return;

    if (simulationStep >= scenario.logs.length) {
      // Completed simulation
      setActiveSimulation(null);
      setSimulationStep(0);
      return;
    }

    const timer = setTimeout(() => {
      const rawLog = scenario.logs[simulationStep];
      const now = new Date();
      const logId = `sim-${activeSimulation}-${simulationStep}`;
      const newLog: LogEvent = {
        ...rawLog,
        id: logId,
        timestamp: now.toLocaleTimeString("en-US", { hour12: false }),
        host: rawLog.host as any,
        source: rawLog.source as any,
        severity: rawLog.severity as any,
      };

      setLogs(prev => [newLog, ...prev]);
      setSimulationLogsInjected(prev => [...prev, logId]);
      
      // Auto-select injected log for immediate AI investigation
      setSelectedLogIds(prev => [...prev, logId]);

      setSimulationStep(prev => prev + 1);
    }, 2000);

    return () => clearTimeout(timer);
  }, [activeSimulation, simulationStep]);

  // Toggle selection of a single log
  const handleToggleLogSelection = (logId: string) => {
    setSelectedLogIds(prev =>
      prev.includes(logId) ? prev.filter(id => id !== logId) : [...prev, logId]
    );
  };

  // Select all logs
  const handleSelectAllLogs = () => {
    setSelectedLogIds(logs.map(l => l.id));
  };

  // Clear logs list
  const handleClearLogs = () => {
    setLogs([]);
    setSelectedLogIds([]);
    setAiReport(null);
  };

  // Run AI investigation on selected logs via Express server-side Gemini API
  const handleGenerateAIReport = async () => {
    if (selectedLogIds.length === 0) return;

    setAiLoading(true);
    setAiError(null);

    const logsToAnalyze = logs.filter(l => selectedLogIds.includes(l.id));

    try {
      const res = await fetch("/api/threats/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs: logsToAnalyze })
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to generate AI Security Report.");
      }

      const data = await res.json();
      setAiReport(data);
    } catch (err: any) {
      console.error("AI Report generation error:", err);
      setAiError(err.message || "An unexpected error occurred during investigation.");
    } finally {
      setAiLoading(false);
    }
  };

  // Launch simulated attack scenario
  const handleStartSimulation = (scenarioId: string) => {
    handleClearLogs(); // clear previous context for high-impact visual
    setActiveSimulation(scenarioId);
    setSimulationStep(0);
    setSimulationLogsInjected([]);
    setIsStreaming(true);
  };

// Get dynamic chart data from live Splunk hosts
const getHostChartData = () => {

  const hostCounts: Record<string, number> = {};

  logs.forEach((log) => {
    const host = log.host || "Unknown";

    hostCounts[host] = (hostCounts[host] || 0) + 1;
  });


  return Object.entries(hostCounts).map(([host, count]) => ({
    name: host,
    value: count,
    fill: "#22d3ee",
  }));

};


const getTimelineChartData = () => {

  const windows = logs.filter(log =>
  log.host === "Windows_10" ||
  log.sourcetype?.startsWith("WinEventLog") ||
  log.sourcetype?.startsWith("XmlWinEventLog")
).length;


  const linux = logs.filter(log =>
    log.host?.toLowerCase().includes("ram") ||
    log.host?.toLowerCase().includes("kali") ||
    log.index === "linux" ||
    log.sourcetype?.includes("syslog") ||
    log.sourcetype?.includes("auth")
  ).length;


  const network = logs.filter(log =>
    log.host?.toLowerCase().includes("ram") ||
    log.index === "network" ||
    log.sourcetype?.includes("zeek") ||
    log.sourcetype?.includes("suricata")
  ).length;


  return [
    {
      time: new Date().toLocaleTimeString("en-US",{hour12:false}),
      Windows: windows,
      Linux: linux,
      Network: network
    }
  ];
};

  const activeScenario = scenarios.find(s => s.id === activeSimulation);

  return (
    <div className="min-h-screen bg-[#05070a] text-[#e0e6ed] flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-300 relative overflow-hidden">
      {/* Background Atmosphere */}
      <div className="absolute top-0 left-0 w-full h-full pointer-events-none z-0">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-[#00f2ff] opacity-[0.03] blur-[120px] rounded-full"></div>
        <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-[#ff0055] opacity-[0.04] blur-[150px] rounded-full"></div>
      </div>

      {/* Dynamic Simulation Top Status Header banner */}
      {activeScenario && (
        <div className="bg-rose-950/90 border-b border-rose-800/40 text-rose-200 px-4 py-2.5 text-xs font-mono flex items-center justify-between select-none animate-pulse relative z-10">
          <div className="flex items-center gap-2">
            <Skull className="w-4 h-4 text-rose-400 animate-spin" />
            <span>
              <strong>ATTACK CAMPAIGN SIMULATION ACTIVE:</strong> {activeScenario.name} (Step {simulationStep}/{activeScenario.logs.length})
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping"></span>
            <span>Simulating live Splunk log transmission...</span>
          </div>
        </div>
      )}

      {/* Top Banner Navigation */}
      <header className="border-b border-white/10 bg-[#0a0c10]/80 backdrop-blur-md sticky top-0 z-40 px-6 py-4 flex flex-col lg:flex-row items-center justify-between gap-4 relative">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(34,211,238,0.4)] text-black font-black text-xs">
              S-AI
            </div>
            <span className="absolute -bottom-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-cyan-400 border-2 border-[#05070a] text-[8px] text-black font-bold font-mono">
              UF
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-sm font-bold tracking-widest uppercase text-[#e0e6ed]">CYBER_NEXSUS SIEM</h1>
              <span className="text-[10px] bg-white/5 text-cyan-400/80 font-mono border border-white/10 rounded px-2 py-0.5">
                v1.4.2 LIVE_ENV
              </span>
            </div>
            <p className="text-[10px] text-cyan-400/70 font-mono uppercase tracking-wider mt-0.5">HACKATHON_MODE // CROSS_VM_CORRELATION</p>
          </div>
        </div>

        {/* Navigation & Status controls */}
        <div className="flex flex-wrap items-center justify-center lg:justify-end gap-6 w-full lg:w-auto">
          {/* Ingest statistics & SIEM metrics */}
          <div className="hidden sm:flex items-center gap-5 text-[11px] font-mono tracking-tighter">
            <div className="flex flex-col items-end">
              <span className="text-white/40 uppercase text-[9px]">Ingest Rate</span>
              <span className="text-cyan-400 font-bold">1.4k EPS</span>
            </div>
            <div className="flex flex-col items-end border-l border-white/10 pl-5">
              <span className="text-white/40 uppercase text-[9px]">SIEM Time</span>
              <span className="text-slate-300 font-semibold">{currentTime}</span>
            </div>
            <div className="flex flex-col items-end border-l border-white/10 pl-5">
              <span className="text-white/40 uppercase text-[9px]">Uptime</span>
              <span className="text-green-400 font-bold">168:12:04</span>
            </div>
          </div>

          {/* Active incidents indicator */}
          {logs.filter(l => l.severity === "high" || l.severity === "critical").length > 0 ? (
            <div className="px-3 py-1 border border-red-500/50 bg-red-500/10 rounded text-red-500 text-[10px] font-mono animate-pulse font-bold select-none tracking-widest">
              {logs.filter(l => l.severity === "high" || l.severity === "critical").length} ACTIVE INCIDENTS
            </div>
          ) : (
            <div className="px-3 py-1 border border-green-500/30 bg-green-500/5 rounded text-green-400 text-[10px] font-mono font-medium select-none tracking-widest">
              0 INCIDENTS
            </div>
          )}

          {/* Navigation Tab selection */}
          <div className="flex bg-white/5 p-1 border border-white/10 rounded-xl">
            <button
              onClick={() => setActiveTab("monitor")}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-mono font-semibold rounded-lg transition-all ${
                activeTab === "monitor"
                  ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(34,211,238,0.15)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              SIEM Dashboard
            </button>
            <button
              onClick={() => setActiveTab("guide")}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-mono font-semibold rounded-lg transition-all ${
                activeTab === "guide"
                  ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(34,211,238,0.15)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              Log Forwarder Guide
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 p-6 space-y-6 max-w-[1600px] mx-auto w-full relative z-10">
        {activeTab === "monitor" ? (
          <>
            {/* Top Metric Stats Summary row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Risk Score Dial Card */}
              <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 flex flex-col items-center justify-center relative shadow-2xl overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-b from-white/5 to-transparent pointer-events-none"></div>
                <h3 className="text-[10px] font-mono uppercase text-white/40 mb-3 tracking-widest">Current Risk Index</h3>
                <div className="relative flex items-center justify-center mb-1">
                  <svg className="w-28 h-28 transform -rotate-90">
                    <circle cx="56" cy="56" r="50" stroke="currentColor" strokeWidth="4" fill="transparent" className="text-white/5" />
                    <circle cx="56" cy="56" r="50" stroke="currentColor" strokeWidth="4" fill="transparent" 
                      strokeDasharray="314" strokeDashoffset={314 - (314 * riskScore) / 100} className={`${riskScore >= 75 ? "text-rose-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)]" : riskScore >= 50 ? "text-amber-500 drop-shadow-[0_0_8px_rgba(245,158,11,0.6)]" : "text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.6)]"} transition-all duration-1000`} />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-3xl font-black font-mono leading-none ${riskScore >= 75 ? "text-rose-500" : riskScore >= 50 ? "text-amber-500" : "text-emerald-400"}`}>{riskScore}</span>
                    <span className="text-[9px] text-white/40 uppercase tracking-widest mt-1">{riskScore >= 75 ? "High Risk" : riskScore >= 50 ? "Med Risk" : "Nominal"}</span>
                  </div>
                </div>
                <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500 to-transparent opacity-30"></div>
              </div>

              {/* Log stream volume */}
              <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 flex items-center justify-between shadow-2xl relative overflow-hidden group">
                <div className="space-y-1.5">
                  <p className="text-[10px] font-bold font-mono uppercase tracking-widest text-white/40">Total Forwarded Logs</p>
                  <p className="text-3xl font-black font-mono text-cyan-400">{logs.length}</p>
                  <p className="text-[11px] text-[#e0e6ed]/40 font-mono">Buffered Splunk stream</p>
                </div>
                <div className="p-3 bg-white/5 border border-white/10 text-cyan-400 rounded-lg shadow-[0_0_10px_rgba(34,211,238,0.15)]">
                  <Terminal className="w-6 h-6" />
                </div>
                <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-cyan-500/50"></div>
              </div>

              {/* Active alerts count */}
              <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 flex items-center justify-between shadow-2xl relative overflow-hidden group">
                <div className="space-y-1.5">
                  <p className="text-[10px] font-bold font-mono uppercase tracking-widest text-white/40">Triggered Alarms (High/Crit)</p>
                  <p className="text-3xl font-black font-mono text-amber-500">
                    {logs.filter(l => l.severity === "high" || l.severity === "critical").length}
                  </p>
                  <p className="text-[11px] text-[#e0e6ed]/40 font-mono">IDS / Sysmon Signatures</p>
                </div>
                <div className="p-3 bg-white/5 border border-white/10 text-amber-500 rounded-lg shadow-[0_0_10px_rgba(245,158,11,0.15)]">
                  <Flame className="w-6 h-6 text-amber-500" />
                </div>
                <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-amber-500/50"></div>
              </div>

              {/* Active Pipeline Status */}
              <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 flex items-center justify-between shadow-2xl relative overflow-hidden group">
                <div className="space-y-1.5">
                  <p className="text-[10px] font-bold font-mono uppercase tracking-widest text-white/40">Splunk Forwarders</p>
                  <p className="text-3xl font-black font-mono text-emerald-400">3 <span className="text-xs text-[#e0e6ed]/30 font-normal">/ 3</span></p>
                  <p className="text-[11px] text-[#e0e6ed]/40 font-mono">Windows, Linux, Zeek/Suricata</p>
                </div>
                <div className="p-3 bg-white/5 border border-white/10 text-emerald-400 rounded-lg shadow-[0_0_10px_rgba(16,185,129,0.15)]">
                  <Layers className="w-6 h-6 text-emerald-400" />
                </div>
                <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-emerald-500/50"></div>
              </div>
            </div>

            {/* Middle Section: Visualizations Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Dynamic Log Traffic chart */}
              <div className="lg:col-span-2 bg-[#0d1117] border border-white/5 rounded-xl p-5 shadow-2xl flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <TrendingUp className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-semibold text-slate-200 font-mono">Cross-VM Correlated Log Flow Frequency</h3>
                    </div>
                    <span className="text-[10px] bg-white/5 border border-white/10 px-2 py-0.5 rounded font-mono text-cyan-400">
                      Real-time Feed Rate
                    </span>
                  </div>
                  <div className="h-[180px] w-full mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={timelineData} margin={{ top: 5, right: 5, left: -25, bottom: 5 }}>
                        <defs>
                          <linearGradient id="colorWin" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.25}/>
                            <stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/>
                          </linearGradient>
                          <linearGradient id="colorLinux" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25}/>
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                          </linearGradient>
                          <linearGradient id="colorNet" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ff0055" stopOpacity={0.25}/>
                            <stop offset="95%" stopColor="#ff0055" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="time" stroke="rgba(255,255,255,0.2)" fontSize={10} fontFamily="monospace" />
                        <YAxis stroke="rgba(255,255,255,0.2)" fontSize={10} fontFamily="monospace" />
                        <Tooltip contentStyle={{ backgroundColor: "#0a0c10", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "8px", fontSize: "11px", fontFamily: "monospace", color: "#e0e6ed" }} />
                        <Area type="monotone" dataKey="Windows" stroke="#22d3ee" fillOpacity={1} fill="url(#colorWin)" strokeWidth={2} />
                        <Area type="monotone" dataKey="Linux" stroke="#3b82f6" fillOpacity={1} fill="url(#colorLinux)" strokeWidth={2} />
                        <Area type="monotone" dataKey="Network" stroke="#ff0055" fillOpacity={1} fill="url(#colorNet)" strokeWidth={2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="flex items-center justify-between border-t border-white/5 pt-3 mt-3 text-[10px] font-mono text-white/40">
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-1 bg-[#22d3ee] rounded-full"></span> index=windows (Windows-VM)</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-1 bg-[#3b82f6] rounded-full"></span> index=linux (Kali-VM)</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-1 bg-[#ff0055] rounded-full"></span> index=network (Suricata/Zeek)</span>
                </div>
              </div>

              {/* Log split by host bar chart */}
              <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 shadow-2xl flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-semibold text-slate-200 font-mono">Logs Volume Split by Host</h3>
                    </div>
                  </div>
                  <div className="h-[180px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={getHostChartData()} margin={{ top: 5, right: 5, left: -25, bottom: 5 }}>
                        <XAxis dataKey="name" stroke="rgba(255,255,255,0.2)" fontSize={10} fontFamily="monospace" />
                        <YAxis stroke="rgba(255,255,255,0.2)" fontSize={10} fontFamily="monospace" />
                        <Tooltip cursor={{ fill: "transparent" }} contentStyle={{ backgroundColor: "#0a0c10", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "8px", fontSize: "11px", fontFamily: "monospace", color: "#e0e6ed" }} />
                        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                          {getHostChartData().map((entry, index) => (
                            <Cell
  key={`cell-${index}`}
  fill={entry.fill}
/>                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <p className="text-[10px] text-center text-white/30 font-mono border-t border-white/5 pt-3 mt-3">
                  Log volume balance indices updated 1s ago
                </p>
              </div>
            </div>

            {/* MITRE ATT&CK Matrix Panel */}
            <MitreMatrix
              techniques={mitreTechniques}
              onSelectTechnique={(tech) => setSelectedMitreTech(tech)}
            />

            {/* Bottom Primary Bento Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left Column: Timeline feed (2/3 width) */}
              <div className="lg:col-span-2 space-y-6">
                <ThreatTimeline
                  logs={logs}
                  selectedLogIds={selectedLogIds}
                  onToggleLogSelection={handleToggleLogSelection}
                  onClearLogs={handleClearLogs}
                  isStreaming={isStreaming}
                  onToggleStreaming={() => setIsStreaming(!isStreaming)}
                />
              </div>

              {/* Right Column: AI investigation Panel & Attack Simulation Hub */}
              <div className="space-y-6 flex flex-col">
                {/* AI Investigation Engine */}
                <AIReportView
                  logs={logs}
                  selectedLogIds={selectedLogIds}
                  report={aiReport}
                  loading={aiLoading}
                  error={aiError}
                  onGenerateReport={handleGenerateAIReport}
                  onSelectAllLogsForAnalysis={handleSelectAllLogs}
                />

                {/* Attack Simulator Control Center */}
                <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 shadow-2xl space-y-4">
                  <div className="flex items-center gap-2 pb-3 border-b border-white/5">
                    <Skull className="w-5 h-5 text-rose-500" />
                    <div>
                      <h4 className="text-sm font-semibold text-slate-100 font-mono">Malicious Attack Simulator</h4>
                      <p className="text-[10px] text-white/40 mt-0.5">Inject dynamic mock threats to test SIEM pipelines</p>
                    </div>
                  </div>

                  <div className="space-y-2.5">
                    {scenarios.map(scen => {
                      const isThisSim = activeSimulation === scen.id;
                      return (
                        <div
                          key={scen.id}
                          className={`p-3.5 rounded-xl border transition-all ${
                            isThisSim
                              ? "bg-rose-950/20 border-rose-500 text-rose-100 shadow-[0_0_12px_rgba(239,68,68,0.1)]"
                              : "bg-[#05070a]/50 border-white/5 hover:border-white/10 text-slate-300"
                          }`}
                        >
                          <div className="flex items-start justify-between gap-2.5">
                            <div className="space-y-1">
                              <div className="flex items-center gap-1.5">
                                <span className="text-xs font-bold text-slate-200 font-mono">{scen.name}</span>
                                <span className="text-[9px] bg-white/5 border border-white/10 text-[#22d3ee] px-1.5 py-0.2 rounded font-mono">
                                  Risk: {scen.impactRisk}
                                </span>
                              </div>
                              <p className="text-[11px] text-white/40 leading-normal">{scen.description}</p>
                            </div>

                            <button
                              disabled={!!activeSimulation}
                              onClick={() => handleStartSimulation(scen.id)}
                              className={`p-1.5 rounded-lg border transition ${
                                isThisSim
                                  ? "bg-rose-500/10 text-rose-400 border-rose-500/20 cursor-not-allowed"
                                  : "bg-[#0d1117] hover:bg-white/5 border-white/5 text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed"
                              }`}
                            >
                              {isThisSim ? (
                                <RefreshCw className="w-4 h-4 animate-spin text-rose-400" />
                              ) : (
                                <Plus className="w-4 h-4 text-cyan-400" />
                              )}
                            </button>
                          </div>

                          {/* Steps progress indicator */}
                          {isThisSim && (
                            <div className="mt-3 pt-3 border-t border-rose-900/30 space-y-1.5">
                              <p className="text-[10px] font-mono font-bold text-rose-300">ACTIVE SEQUENCER:</p>
                              <div className="space-y-1 text-[10px] font-mono">
                                {scen.steps.map((step, idx) => {
                                  const isDone = simulationStep > idx;
                                  const isCurrent = simulationStep === idx;
                                  return (
                                    <div key={idx} className="flex items-center gap-1.5">
                                      <span className={`w-1.5 h-1.5 rounded-full ${isDone ? "bg-emerald-400" : isCurrent ? "bg-rose-400 animate-ping" : "bg-[#05070a]"}`}></span>
                                      <span className={isDone ? "text-slate-500 line-through" : isCurrent ? "text-rose-200 font-bold" : "text-slate-400"}>{step}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </>
        ) : (
          /* Splunk configuration Guide tab */
          <SplunkGuide />
        )}
      </main>

      {/* MITRE Info Dialog popover */}
      {selectedMitreTech && (
        <div className="fixed inset-0 bg-[#05070a]/80 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="bg-[#0d1117] border border-white/10 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl relative select-none">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-mono font-bold text-rose-400">{selectedMitreTech.id}</span>
                <h4 className="text-base font-bold text-slate-100 font-sans mt-0.5">{selectedMitreTech.name}</h4>
              </div>
              <span className="text-[10px] bg-[#05070a] border border-white/10 px-2 py-0.5 rounded font-mono uppercase font-bold text-[#22d3ee]">
                {selectedMitreTech.tactic}
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-mono bg-[#05070a] p-3.5 rounded-lg border border-white/5">
              {selectedMitreTech.description}
            </p>

            <div className="flex items-center justify-between text-xs border-t border-white/5 pt-4">
              <span className="text-slate-400">
                Active alerts matched in SIEM: <strong className="text-slate-200">{selectedMitreTech.associatedLogsCount}</strong>
              </span>
              <button
                onClick={() => setSelectedMitreTech(null)}
                className="bg-white/5 hover:bg-white/10 text-slate-200 border border-white/10 px-4 py-1.5 rounded-lg text-xs font-mono font-bold transition"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bottom Legal Credit footer */}
      <footer className="border-t border-white/5 py-5 bg-[#0a0c10]/60 text-center text-xs text-white/30 font-mono select-none relative z-10">
        <p>© 2026 Sentinel SIEM. Configured for Hackathon pipeline milestones (Day 1 - Day 9).</p>
      </footer>
    </div>
  );
}
