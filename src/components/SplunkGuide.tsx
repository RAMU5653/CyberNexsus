import React, { useState } from "react";
import { Terminal, Shield, Cpu, BookOpen, Layers, CheckCircle, Copy, Check } from "lucide-react";

export default function SplunkGuide() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<"architecture" | "windows" | "kali" | "network">("architecture");

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const configs = {
    outputsConf: `[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.1.150:9997 # IP of Splunk Indexer (Kali-VM)

[tcpout-server://192.168.1.150:9997]`,
    windowsInputsConf: `# Monitor Windows Security Event Logs
[WinEventLog://Security]
disabled = 0
index = windows
sourcetype = WinEventLog

# Monitor Sysmon Operational Logs
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

# Monitor PowerShell Operational Script Logs
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Microsoft-Windows-PowerShell/Operational`,
    kaliInputsConf: `# Monitor auth.log (SSH, sudo, users logins)
[monitor:///var/log/auth.log]
disabled = 0
index = linux
sourcetype = syslog

# Monitor general syslog
[monitor:///var/log/syslog]
disabled = 0
index = linux
sourcetype = syslog`,
    networkInputsConf: `# Monitor Suricata IDS Alert logs
[monitor:///var/log/suricata/eve.json]
disabled = 0
index = network
sourcetype = _json

# Monitor Zeek connection logs
[monitor:///opt/zeek/logs/current/conn.log]
disabled = 0
index = network
sourcetype = zeek:conn`
  };

  return (
    <div className="bg-[#0d1117] border border-white/5 rounded-xl overflow-hidden shadow-2xl h-full flex flex-col">
      {/* Header */}
      <div className="p-5 border-b border-white/5 bg-[#0a0c10]/60 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 text-cyan-400 rounded-lg border border-cyan-500/20">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">Splunk Forwarder Setup Guide</h2>
            <p className="text-xs text-slate-400">SIEM Logistics & Pipeline Architecture</p>
          </div>
        </div>
        <span className="text-xs bg-[#05070a] px-3 py-1 text-[#22d3ee] font-mono rounded-full border border-white/10">
          Hackathon Companion
        </span>
      </div>

      {/* Tabs */}
      <div className="flex bg-[#05070a] p-2 border-b border-white/5 overflow-x-auto gap-1">
        <button
          onClick={() => setActiveSubTab("architecture")}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-lg transition-all whitespace-nowrap ${
            activeSubTab === "architecture"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold"
              : "text-white/40 hover:text-slate-200 hover:bg-white/5"
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          1. Pipeline Architecture
        </button>
        <button
          onClick={() => setActiveSubTab("windows")}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-lg transition-all whitespace-nowrap ${
            activeSubTab === "windows"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold"
              : "text-white/40 hover:text-slate-200 hover:bg-white/5"
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          2. Windows VM Setup
        </button>
        <button
          onClick={() => setActiveSubTab("kali")}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-lg transition-all whitespace-nowrap ${
            activeSubTab === "kali"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold"
              : "text-white/40 hover:text-slate-200 hover:bg-white/5"
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          3. Kali Linux Setup
        </button>
        <button
          onClick={() => setActiveSubTab("network")}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-lg transition-all whitespace-nowrap ${
            activeSubTab === "network"
              ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold"
              : "text-white/40 hover:text-slate-200 hover:bg-white/5"
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          4. Network Logs Setup
        </button>
      </div>

      {/* Tab Contents */}
      <div className="p-6 flex-1 overflow-y-auto space-y-6">
        {activeSubTab === "architecture" && (
          <div className="space-y-5">
            <div className="bg-cyan-500/5 border border-cyan-500/10 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-cyan-400 font-mono uppercase tracking-wider">Log Forwarder Explanation</h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                For both Windows and Kali Linux, the primary tool used to forward system logs to Splunk Enterprise is the <strong className="text-slate-100">Splunk Universal Forwarder (UF)</strong>.
              </p>
              <p className="text-sm text-slate-400 leading-relaxed">
                The Universal Forwarder is a lightweight, high-performance, and secure agent that monitors designated log paths, compresses and encrypts the stream, and ships the logs to the central Splunk Indexer over port <strong className="text-cyan-400 font-mono">9997</strong>.
              </p>
            </div>

            <div className="space-y-3">
              <h4 className="text-xs font-bold font-mono text-white/30 uppercase tracking-widest">SIEM Data flow pipeline</h4>
              <div className="relative border border-white/5 rounded-xl p-4 bg-[#05070a]/40 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="border border-white/5 bg-[#0d1117]/60 p-3.5 rounded-lg text-center">
                    <p className="text-xs font-mono font-bold text-cyan-400 uppercase">1. Windows VM Logs</p>
                    <p className="text-[11px] text-slate-400 mt-1">Sysmon, WinEvent, PowerShell</p>
                    <div className="mt-2 text-[10px] bg-[#05070a] text-slate-300 py-1 px-2 font-mono rounded border border-white/5">Splunk Universal Forwarder</div>
                  </div>
                  <div className="border border-white/5 bg-[#0d1117]/60 p-3.5 rounded-lg text-center">
                    <p className="text-xs font-mono font-bold text-blue-400 uppercase">2. Kali VM Logs</p>
                    <p className="text-[11px] text-slate-400 mt-1">auth.log, syslog, Linux audits</p>
                    <div className="mt-2 text-[10px] bg-[#05070a] text-slate-300 py-1 px-2 font-mono rounded border border-white/5">Splunk Universal Forwarder</div>
                  </div>
                  <div className="border border-white/5 bg-[#0d1117]/60 p-3.5 rounded-lg text-center">
                    <p className="text-xs font-mono font-bold text-rose-400 uppercase">3. Network Sensor</p>
                    <p className="text-[11px] text-slate-400 mt-1">Suricata IDS, Zeek Logs, PCAP</p>
                    <div className="mt-2 text-[10px] bg-[#05070a] text-slate-300 py-1 px-2 font-mono rounded border border-white/5">Suricata / Zeek Engines</div>
                  </div>
                </div>

                <div className="flex justify-center my-1">
                  <span className="text-xs text-cyan-400 font-mono animate-pulse">▼ Port 9997 (TLS Encrypted Stream)</span>
                </div>

                <div className="bg-[#0d1117] border border-white/10 p-4 rounded-lg text-center">
                  <p className="text-sm font-mono font-bold text-slate-100">Splunk Enterprise Indexer (Kali Host)</p>
                  <p className="text-xs text-slate-400 mt-1">Indexes all raw inputs into specific indexes:</p>
                  <div className="flex flex-wrap justify-center gap-1.5 mt-3">
                    <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-900/50 py-1 px-2.5 rounded-full font-mono">index=windows</span>
                    <span className="text-[10px] bg-blue-950/80 text-blue-300 border border-blue-900/50 py-1 px-2.5 rounded-full font-mono">index=linux</span>
                    <span className="text-[10px] bg-rose-950/80 text-rose-300 border border-rose-900/50 py-1 px-2.5 rounded-full font-mono">index=network</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="border border-white/5 rounded-xl p-4 bg-[#05070a]/20 space-y-3">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-mono font-semibold text-slate-200">How to Setup Shared outputs.conf</span>
              </div>
              <p className="text-xs text-slate-400">
                On both VMs, you must configure <code className="text-cyan-400">C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf</code> (Windows) or <code className="text-cyan-400">/opt/splunkforwarder/etc/system/local/outputs.conf</code> (Kali) to define where logs should go:
              </p>
              <div className="relative rounded-lg overflow-hidden bg-[#05070a] border border-white/5">
                <button
                  onClick={() => copyToClipboard(configs.outputsConf, "outputs")}
                  className="absolute right-2 top-2 p-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-slate-400 transition"
                >
                  {copiedId === "outputs" ? <Check className="w-3.5 h-3.5 text-cyan-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <pre className="p-4 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre leading-relaxed">{configs.outputsConf}</pre>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === "windows" && (
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-100 font-mono">Windows Splunk Forwarder Setup</h3>
              <p className="text-xs text-slate-400">Configuration of Sysmon, PowerShell, and Event logging (Day 2 Milestone)</p>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <p className="flex gap-2">
                <span className="text-[#22d3ee] font-bold">1.</span>
                <span>Download the Splunk Universal Forwarder MSI installer and run it on Windows-VM.</span>
              </p>
              <p className="flex gap-2">
                <span className="text-[#22d3ee] font-bold">2.</span>
                <span>Install Sysmon by Microsoft Sysinternals using SwiftOnSecurity config:</span>
              </p>
              <div className="bg-[#05070a] p-2.5 rounded-lg border border-white/5 font-mono text-[11px] text-cyan-400 flex justify-between items-center">
                <span>sysmon.exe -accepteula -i sysmonconfig-export.xml</span>
                <button onClick={() => copyToClipboard("sysmon.exe -accepteula -i sysmonconfig-export.xml", "sysmonCmd")} className="text-white/20 hover:text-white/40">
                  {copiedId === "sysmonCmd" ? <Check className="w-3 h-3 text-cyan-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <p className="flex gap-2 mt-2">
                <span className="text-[#22d3ee] font-bold">3.</span>
                <span>Configure Windows Forwarder <code className="text-[#22d3ee]">inputs.conf</code> at <code className="text-slate-300">C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf</code>:</span>
              </p>
            </div>

            <div className="relative rounded-lg overflow-hidden bg-[#05070a] border border-white/5 mt-2">
              <div className="flex items-center justify-between bg-[#0d1117] px-3 py-1.5 border-b border-white/5">
                <span className="text-[10px] font-mono text-white/30">inputs.conf (Windows)</span>
                <button
                  onClick={() => copyToClipboard(configs.windowsInputsConf, "winInputs")}
                  className="p-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-slate-400 transition"
                >
                  {copiedId === "winInputs" ? <Check className="w-3 h-3 text-cyan-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <pre className="p-3 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre leading-relaxed max-h-[250px]">{configs.windowsInputsConf}</pre>
            </div>
          </div>
        )}

        {activeSubTab === "kali" && (
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-100 font-mono">Kali Linux Splunk Forwarder Setup</h3>
              <p className="text-xs text-slate-400">Configuring daemon and authentication file tracking (Day 3 Milestone)</p>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <p className="flex gap-2">
                <span className="text-cyan-400 font-bold">1.</span>
                <span>Download the Splunk Universal Forwarder deb package on Kali Linux and install it:</span>
              </p>
              <div className="bg-[#05070a] p-2.5 rounded-lg border border-white/5 font-mono text-[11px] text-[#22d3ee] flex justify-between items-center">
                <span>sudo dpkg -i splunkforwarder-*.deb</span>
                <button onClick={() => copyToClipboard("sudo dpkg -i splunkforwarder-*.deb", "kaliInstall")} className="text-white/20 hover:text-white/40">
                  {copiedId === "kaliInstall" ? <Check className="w-3 h-3 text-cyan-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <p className="flex gap-2 mt-2">
                <span className="text-[#22d3ee] font-bold">2.</span>
                <span>Start and enable the forwarder daemon:</span>
              </p>
              <div className="bg-[#05070a] p-2.5 rounded-lg border border-white/5 font-mono text-[11px] text-[#22d3ee] flex justify-between items-center">
                <span>sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes</span>
                <button onClick={() => copyToClipboard("sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes", "kaliStart")} className="text-white/20 hover:text-white/40">
                  {copiedId === "kaliStart" ? <Check className="w-3 h-3 text-cyan-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <p className="flex gap-2 mt-2">
                <span className="text-[#22d3ee] font-bold">3.</span>
                <span>Edit <code className="text-[#22d3ee]">/opt/splunkforwarder/etc/system/local/inputs.conf</code> to add Kali system inputs:</span>
              </p>
            </div>

            <div className="relative rounded-lg overflow-hidden bg-[#05070a] border border-white/5 mt-2">
              <div className="flex items-center justify-between bg-[#0d1117] px-3 py-1.5 border-b border-white/5">
                <span className="text-[10px] font-mono text-white/30">inputs.conf (Kali Linux)</span>
                <button
                  onClick={() => copyToClipboard(configs.kaliInputsConf, "kaliInputs")}
                  className="p-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-slate-400 transition"
                >
                  {copiedId === "kaliInputs" ? <Check className="w-3 h-3 text-cyan-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <pre className="p-3 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre leading-relaxed">{configs.kaliInputsConf}</pre>
            </div>
          </div>
        )}

        {activeSubTab === "network" && (
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-100 font-mono">Suricata & Zeek Network Logs Integration</h3>
              <p className="text-xs text-slate-400">Connecting network analysis telemetry output to Splunk (Day 4 Milestone)</p>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <p className="flex gap-2">
                <span className="text-[#22d3ee] font-bold">1.</span>
                <span>Install Suricata IDS and Zeek Network Security Monitor on the network gateway or VM interfaces.</span>
              </p>
              <p className="flex gap-2 font-mono text-[11px] text-[#22d3ee] pl-4 bg-[#05070a]/40 p-2 rounded border border-white/5">
                <span>sudo bg-cyan-950/30 apt install suricata zeek-core -y</span>
              </p>
              <p className="flex gap-2 mt-2">
                <span className="text-[#22d3ee] font-bold">2.</span>
                <span>Suricata outputs alerts dynamically to <code className="text-cyan-400">/var/log/suricata/eve.json</code> and Zeek streams connections to <code className="text-cyan-400">/opt/zeek/logs/current/conn.log</code>.</span>
              </p>
              <p className="flex gap-2 mt-1">
                <span className="text-[#22d3ee] font-bold">3.</span>
                <span>Append the following monitors to your Linux Splunk Forwarder <code className="text-cyan-400">inputs.conf</code>:</span>
              </p>
            </div>

            <div className="relative rounded-lg overflow-hidden bg-[#05070a] border border-white/5 mt-2">
              <div className="flex items-center justify-between bg-[#0d1117] px-3 py-1.5 border-b border-white/5">
                <span className="text-[10px] font-mono text-white/30">inputs.conf (Network Monitoring)</span>
                <button
                  onClick={() => copyToClipboard(configs.networkInputsConf, "networkInputs")}
                  className="p-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-slate-400 transition"
                >
                  {copiedId === "networkInputs" ? <Check className="w-3 h-3 text-cyan-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <pre className="p-3 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre leading-relaxed">{configs.networkInputsConf}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
