import React, { useState } from "react";
import { LogEvent } from "../types";
import { Terminal, Shield, Play, Pause, Trash2, Search, Filter, ShieldAlert, Cpu, Network, CheckSquare, Square } from "lucide-react";

interface ThreatTimelineProps {
  logs: LogEvent[];
  selectedLogIds: string[];
  onToggleLogSelection: (logId: string) => void;
  onClearLogs: () => void;
  isStreaming: boolean;
  onToggleStreaming: () => void;
}

export default function ThreatTimeline({
  logs,
  selectedLogIds,
  onToggleLogSelection,
  onClearLogs,
  isStreaming,
  onToggleStreaming
}: ThreatTimelineProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [hostFilter, setHostFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  // Filter logs
  const filteredLogs = logs.filter(log => {
    const matchesSearch =
      log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.mitreId && log.mitreId.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (log.mitreName && log.mitreName.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesHost =
  hostFilter === "all" ||

  (
    hostFilter === "Windows" &&
    (
      log.host?.toLowerCase() === "windows_10" ||
      log.index === "windows-10" ||
      log.sourcetype?.toLowerCase().includes("wineventlog") ||
      log.sourcetype?.toLowerCase().includes("xmlwineventlog")
    )
  ) ||

  (
    hostFilter === "Kali" &&
    (
      log.index === "linux" ||
      log.host?.toLowerCase() === "ram"
    )
  ) ||

  (
    hostFilter === "Network" &&
    (
      log.index === "network" ||
      log.sourcetype?.toLowerCase().includes("zeek") ||
      log.sourcetype?.toLowerCase().includes("suricata")
    )
  );
    const matchesSeverity = severityFilter === "all" || log.severity === severityFilter;

    return matchesSearch && matchesHost && matchesSeverity;
  });

  const getHostIcon = (host: string) => {
    switch (host) {
      case "Windows-VM":
        return <Cpu className="w-3.5 h-3.5 text-blue-400" />;
      case "Kali-VM":
        return <Terminal className="w-3.5 h-3.5 text-sky-400" />;
      default:
        return <Network className="w-3.5 h-3.5 text-amber-400" />;
    }
  };

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-rose-950/80 text-rose-300 border border-rose-800/80";
      case "high":
        return "bg-amber-950/80 text-amber-300 border border-amber-800/80";
      case "medium":
        return "bg-yellow-950/80 text-yellow-300 border border-yellow-800/80";
      default:
        return "bg-slate-900 text-slate-400 border border-slate-800";
    }
  };

  const getSourceBadgeColor = (source: string) => {
    switch (source) {
      case "Sysmon":
        return "bg-blue-950/50 text-blue-400 border border-blue-900/30";
      case "PowerShell":
        return "bg-indigo-950/50 text-indigo-400 border border-indigo-900/30";
      case "auth.log":
        return "bg-sky-950/50 text-sky-400 border border-sky-900/30";
      case "syslog":
        return "bg-slate-950/60 text-slate-400 border border-slate-800";
      case "Suricata":
        return "bg-emerald-950/50 text-emerald-400 border border-emerald-900/30";
      default:
        return "bg-orange-950/50 text-orange-400 border border-orange-900/30";
    }
  };

  return (
    <div className="bg-[#0d1117] border border-white/5 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[550px]">
      {/* Top Controls Bar */}
      <div className="p-4 bg-[#0a0c10]/60 border-b border-white/5 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider">Live SIEM Log Feed (Forwarded Events)</h3>
          <span className="text-[10px] bg-white/5 text-white/40 border border-white/10 px-2 py-0.5 rounded font-mono">
            {filteredLogs.length} events
          </span>
        </div>

        {/* Streaming & Management Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={onToggleStreaming}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition ${
              isStreaming
                ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20 hover:bg-cyan-500/20"
                : "bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20"
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-3.5 h-3.5 animate-pulse" /> Live Streaming
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" /> Paused
              </>
            )}
          </button>
          <button
            onClick={onClearLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-[#05070a] hover:bg-white/5 text-slate-300 border border-white/10 transition"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear Stream
          </button>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="p-3 bg-[#0a0c10]/30 border-b border-white/5 flex flex-col sm:flex-row gap-2.5">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-white/20" />
          <input
            type="text"
            placeholder="Search logs by keyword, script command, process name..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#05070a] border border-white/5 hover:border-white/10 focus:border-cyan-500 focus:outline-none text-xs rounded-lg text-slate-200 font-mono transition"
          />
        </div>

        {/* Host Filter */}
        <div className="flex items-center gap-1.5 bg-[#05070a] px-2.5 py-1 rounded-lg border border-white/5 min-w-[130px]">
          <Filter className="w-3 h-3 text-white/30" />
          <select
            value={hostFilter}
            onChange={e => setHostFilter(e.target.value)}
            className="bg-transparent text-[11px] font-mono text-slate-300 focus:outline-none w-full cursor-pointer"
          >
            <option value="all" className="bg-[#0d1117] text-slate-300">All Hosts</option>
            <option value="Windows" className="bg-[#0d1117] text-slate-300">
  Windows_10
</option>

<option value="Kali" className="bg-[#0d1117] text-slate-300">
  Kali Linux
</option>

<option value="Network" className="bg-[#0d1117] text-slate-300">
  Network Sensor
</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-1.5 bg-[#05070a] px-2.5 py-1 rounded-lg border border-white/5 min-w-[130px]">
          <ShieldAlert className="w-3 h-3 text-white/30" />
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-transparent text-[11px] font-mono text-slate-300 focus:outline-none w-full cursor-pointer"
          >
            <option value="all" className="bg-[#0d1117] text-slate-300">All Severities</option>
            <option value="low" className="bg-[#0d1117] text-slate-300">Low</option>
            <option value="medium" className="bg-[#0d1117] text-slate-300">Medium</option>
            <option value="high" className="bg-[#0d1117] text-slate-300">High</option>
            <option value="critical" className="bg-[#0d1117] text-slate-300">Critical</option>
          </select>
        </div>
      </div>

      {/* Log Feed Table */}
      <div className="flex-1 overflow-y-auto bg-[#0a0c10]/20">
        {filteredLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full p-8 text-center">
            <Terminal className="w-12 h-12 text-white/10 mb-2.5" />
            <p className="text-sm font-mono text-white/40">No matching security logs generated</p>
            <p className="text-xs text-white/20 mt-1">Try injecting an attack simulation to populate the forwarder pipelines.</p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-[#0a0c10]/60 text-[10px] uppercase font-bold text-white/30 border-b border-white/5 select-none">
                <th className="py-2.5 px-3 w-[45px] text-center">AI</th>
                <th className="py-2.5 px-3 w-[70px]">Time</th>
                <th className="py-2.5 px-3 w-[120px]">Host</th>
                <th className="py-2.5 px-3 w-[100px]">Source</th>
                <th className="py-2.5 px-3 w-[80px]">Severity</th>
                <th className="py-2.5 px-3">Raw Log Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredLogs.map(log => {
                const isSelected = selectedLogIds.includes(log.id);
                const isExpanded = expandedLogId === log.id;
                return (
                  <React.Fragment key={log.id}>
                    <tr
                      onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                      className={`hover:bg-white/5 transition-colors cursor-pointer ${
                        isSelected ? "bg-cyan-500/5 border-l-2 border-l-cyan-400" : ""
                      }`}
                    >
                      {/* Checkbox for AI Analysis */}
                      <td
                        className="py-2.5 px-3 text-center"
                        onClick={e => {
                          e.stopPropagation();
                          onToggleLogSelection(log.id);
                        }}
                      >
                        <button className="text-white/20 hover:text-cyan-400 transition">
                          {isSelected ? (
                            <CheckSquare className="w-4 h-4 text-cyan-400" />
                          ) : (
                            <Square className="w-4 h-4" />
                          )}
                        </button>
                      </td>

                      {/* Time */}
                      <td className="py-2.5 px-3 text-white/40 whitespace-nowrap">{log.timestamp}</td>

                      {/* Host */}
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
                          {getHostIcon(log.host)}
                          <span>{log.host}</span>
                        </div>
                      </td>

                      {/* Source */}
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded-md uppercase tracking-tight ${getSourceBadgeColor(log.source)}`}>
                          {log.source}
                        </span>
                      </td>

                      {/* Severity */}
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded-md uppercase tracking-tight ${getSeverityBadgeColor(log.severity)}`}>
                          {log.severity}
                        </span>
                      </td>

                      {/* Message */}
                      <td className="py-2.5 px-3 text-slate-300 truncate max-w-[250px] sm:max-w-md lg:max-w-xl">
                        {log.mitreId && (
                          <span className="text-[10px] bg-rose-950/30 text-rose-400 border border-rose-900/40 px-1.5 py-0.5 rounded font-bold mr-1.5 uppercase font-mono">
                            {log.mitreId}
                          </span>
                        )}
                        <span>{log.message}</span>
                      </td>
                    </tr>

                    {/* Expanded Detail Panel */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={6} className="bg-[#05070a]/80 p-4 border-t border-b border-white/5">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <p className="text-xs font-bold text-white/40 uppercase tracking-wider font-mono">Log Diagnostics</p>
                              <div className="bg-[#0d1117]/80 p-3 rounded-lg border border-white/5 space-y-1">
                                <p className="text-slate-300">
                                  <span className="text-white/20">Log ID: </span>
                                  {log.id}
                                </p>
                                <p className="text-slate-300">
                                  <span className="text-white/20">Timestamp: </span>
                                  {log.timestamp} (Forwarded real-time)
                                </p>
                                <p className="text-slate-300">
                                  <span className="text-white/20">Tactic/Category: </span>
                                  <span className="text-[#22d3ee] font-semibold">{log.category}</span>
                                </p>
                                {log.mitreId && (
                                  <p className="text-slate-300">
                                    <span className="text-white/20">MITRE Technique: </span>
                                    <span className="text-rose-400 font-semibold">
                                      {log.mitreId} - {log.mitreName}
                                    </span>
                                  </p>
                                )}
                              </div>
                            </div>

                            <div className="space-y-2">
                              <p className="text-xs font-bold text-white/40 uppercase tracking-wider font-mono">Parsed Metadata Parameters</p>
                              <div className="bg-[#0d1117]/80 p-3 rounded-lg border border-white/5">
                                <pre className="text-[11px] text-cyan-300 overflow-x-auto whitespace-pre leading-relaxed">
                                  {JSON.stringify(log.details, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </div>

                          <div className="mt-3.5 pt-3.5 border-t border-white/5 flex items-center justify-between">
                            <p className="text-[11px] text-white/40">
                              Selected this log for AI analysis? Use the checkboxes on the left, then click the AI Investigation button.
                            </p>
                            <button
                              onClick={() => onToggleLogSelection(log.id)}
                              className={`px-3 py-1 rounded text-xs font-mono font-bold border transition ${
                                isSelected
                                  ? "bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20"
                                  : "bg-cyan-500/10 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/20"
                              }`}
                            >
                              {isSelected ? "Remove from AI scope" : "Select for AI analysis"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
