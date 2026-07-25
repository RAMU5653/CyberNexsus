import React from "react";
import { IncidentReport, LogEvent } from "../types";
import { ShieldAlert, AlertTriangle, Play, Sparkles, CheckCircle, RefreshCw, AlertCircle } from "lucide-react";

interface AIReportViewProps {
  logs: LogEvent[];
  selectedLogIds: string[];
  report: IncidentReport | null;
  loading: boolean;
  error: string | null;
  onGenerateReport: () => void;
  onSelectAllLogsForAnalysis: () => void;
}

export default function AIReportView({
  logs,
  selectedLogIds,
  report,
  loading,
  error,
  onGenerateReport,
  onSelectAllLogsForAnalysis
}: AIReportViewProps) {
  const selectedLogsCount = selectedLogIds.length;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-rose-400 border-rose-500 bg-rose-950/20";
      case "high":
        return "text-amber-400 border-amber-500 bg-amber-950/20";
      case "medium":
        return "text-yellow-400 border-yellow-500 bg-yellow-950/20";
      default:
        return "text-slate-400 border-slate-500 bg-slate-900/40";
    }
  };

  return (
    <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 shadow-2xl h-full flex flex-col justify-between">
      <div>
        {/* Panel Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/5 mb-5">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-cyan-400 animate-cyber" />
            <h3 className="text-sm font-semibold text-slate-100 font-mono uppercase tracking-wider">AI Threat Investigation Engine</h3>
          </div>
          <span className="text-[10px] bg-[#05070a] border border-white/10 font-mono text-cyan-400/80 px-2.5 py-1 rounded">
            Scope: {selectedLogsCount} {selectedLogsCount === 1 ? "log" : "logs"}
          </span>
        </div>

        {/* Content Box */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 space-y-4 text-center">
            <div className="relative">
              <div className="w-12 h-12 border-4 border-cyan-500/10 border-t-cyan-400 rounded-full animate-spin"></div>
              <Sparkles className="w-5 h-5 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
            </div>
            <div className="space-y-1">
              <p className="text-sm font-mono text-slate-200">AI Investigator analyzing payload correlation...</p>
              <p className="text-xs text-white/40">Cross-correlating Sysmon EventIDs, Linux syslog, and Suricata IDS alerts...</p>
            </div>
            <div className="text-[10px] bg-[#05070a] px-3 py-1.5 text-cyan-400 font-mono border border-cyan-950 rounded select-none animate-pulse">
              [SYSTEM_INTELLIGENCE: CORRELATING MITRE PATHS]
            </div>
          </div>
        ) : error ? (
          <div className="p-4 bg-rose-500/5 border border-rose-500/20 rounded-xl space-y-2 text-center my-4">
            <AlertCircle className="w-8 h-8 text-rose-400 mx-auto" />
            <p className="text-sm font-mono font-semibold text-rose-300">Analysis Request Failed</p>
            <p className="text-xs text-white/40">{error}</p>
            <button
              onClick={onGenerateReport}
              className="mt-2 text-xs font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30 px-3 py-1.5 rounded hover:bg-rose-500/30 transition"
            >
              Retry AI Correlation
            </button>
          </div>
        ) : report ? (
          <div className="space-y-5 overflow-y-auto max-h-[420px] pr-1.5">
            {/* Summary Block */}
            <div className="flex flex-col sm:flex-row items-start justify-between gap-4 bg-[#05070a] p-4 rounded-xl border border-white/5">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border uppercase tracking-widest ${getSeverityColor(report.severity)}`}>
                    {report.severity} severity
                  </span>
                  <span className="text-xs font-mono text-white/30">Threat Sentinel Audit</span>
                </div>
                <h4 className="text-base font-bold text-slate-100 font-sans tracking-tight">{report.title}</h4>
                <p className="text-xs text-slate-300 leading-relaxed">{report.summary}</p>
              </div>

              {/* Risk Score Bubble */}
              <div className="flex flex-col items-center justify-center p-3 bg-[#0d1117] border border-white/5 rounded-lg min-w-[80px] self-center sm:self-auto">
                <span className="text-[10px] font-mono text-white/30 uppercase font-bold">Composite</span>
                <span className={`text-2xl font-black font-mono mt-1 ${
                  report.riskScore >= 80 ? "text-rose-500" : report.riskScore >= 50 ? "text-amber-500" : "text-emerald-400"
                }`}>
                  {report.riskScore}
                </span>
                <span className="text-[9px] font-mono text-white/20 mt-0.5">/100</span>
              </div>
            </div>

            {/* MITRE ATT&CK tactics list */}
            {report.mitreMapping && report.mitreMapping.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-[11px] font-bold font-mono text-white/30 uppercase tracking-wider">Identified MITRE Techniques</h5>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {report.mitreMapping.map((tech, idx) => (
                    <div key={idx} className="bg-[#05070a] p-2.5 rounded-lg border border-white/5 flex items-center justify-between">
                      <div>
                        <p className="text-[11px] font-bold text-rose-400 font-mono">{tech.techniqueId}</p>
                        <p className="text-xs font-semibold text-slate-200 mt-0.5 leading-snug">{tech.techniqueName}</p>
                      </div>
                      <span className="text-[9px] bg-[#0d1117] px-2 py-0.5 text-[#22d3ee] rounded-full border border-white/5 uppercase font-mono font-bold">
                        {tech.tactic}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Attack Timeline Reconstruction */}
            {report.timeline && report.timeline.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-[11px] font-bold font-mono text-white/30 uppercase tracking-wider">Correlated Attack Timeline</h5>
                <div className="border border-white/5 rounded-xl bg-[#05070a] p-3.5 space-y-3 relative overflow-hidden">
                  <div className="absolute left-[19px] top-4 bottom-4 w-0.5 bg-white/5"></div>
                  {report.timeline.map((item, idx) => (
                    <div key={idx} className="flex gap-4 relative z-10 items-start">
                      <div className="w-2.5 h-2.5 rounded-full bg-rose-500 ring-4 ring-[#05070a] border border-slate-100 flex-shrink-0 mt-1"></div>
                      <div className="text-xs">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-slate-400 font-bold">{item.time}</span>
                          <span className="text-[9px] bg-white/5 px-1.5 py-0.2 rounded text-cyan-400 border border-white/10 font-mono uppercase">{item.host}</span>
                        </div>
                        <p className="text-slate-300 mt-1 font-semibold leading-relaxed">{item.event}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Technical Narrative */}
            <div className="space-y-2">
              <h5 className="text-[11px] font-bold font-mono text-white/30 uppercase tracking-wider">Deep Technical Analysis</h5>
              <div className="bg-[#05070a] p-3.5 rounded-xl border border-white/5 text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-mono">
                {report.technicalDetails}
              </div>
            </div>

            {/* Mitigation / Remediation playbook */}
            {report.remediationSteps && report.remediationSteps.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-[11px] font-bold font-mono text-white/30 uppercase tracking-wider">Remediation & Incident Response Playbook</h5>
                <div className="bg-[#05070a]/40 p-4 border border-white/5 rounded-xl space-y-2.5">
                  {report.remediationSteps.map((step, idx) => (
                    <div key={idx} className="flex gap-2.5 text-xs text-slate-300 items-start">
                      <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <p className="leading-relaxed">{step}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-20 text-center border border-dashed border-white/10 rounded-xl bg-[#05070a]/20 px-4">
            <ShieldAlert className="w-12 h-12 text-white/10 mb-3" />
            <p className="text-sm font-mono text-slate-300 font-semibold">Incident Report Sandbox</p>
            <p className="text-xs text-white/30 max-w-sm mt-1 mb-4">
              To trigger a dynamic AI incident investigation, select logs from the live feed on the left, or inject an attack simulation campaign!
            </p>
            {selectedLogsCount > 0 ? (
              <button
                onClick={onGenerateReport}
                className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-500 hover:opacity-95 text-black px-4 py-2 text-xs font-bold font-mono rounded-lg transition shadow-lg shadow-cyan-500/10"
              >
                <Sparkles className="w-4 h-4" /> Run AI Investigation ({selectedLogsCount} Logs)
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={onSelectAllLogsForAnalysis}
                  className="px-3.5 py-2 bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs font-mono font-semibold rounded-lg transition"
                >
                  Select All Logs for AI
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer trigger button when report is visible to quickly run another */}
      {report && !loading && (
        <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
          <p className="text-[11px] text-white/30 font-mono">Powered by Gemini AI model series</p>
          <button
            onClick={onGenerateReport}
            disabled={selectedLogsCount === 0}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
              selectedLogsCount > 0
                ? "bg-gradient-to-r from-cyan-500 to-blue-500 text-black hover:opacity-95"
                : "bg-white/5 text-white/20 border border-white/10 cursor-not-allowed"
            }`}
          >
            <RefreshCw className="w-3.5 h-3.5" /> Re-analyze Scope
          </button>
        </div>
      )}
    </div>
  );
}
