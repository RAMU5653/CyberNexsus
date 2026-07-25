import React, { useState } from "react";
import { Shield, Eye, Flame, AlertCircle } from "lucide-react";
import { MITRETechnique } from "../types";

interface MitreMatrixProps {
  techniques: MITRETechnique[];
  onSelectTechnique: (technique: MITRETechnique | null) => void;
}

export default function MitreMatrix({ techniques, onSelectTechnique }: MitreMatrixProps) {
  const [hoveredTech, setHoveredTech] = useState<string | null>(null);

  // Group by Tactic
  const tactics = [
    { name: "Reconnaissance", color: "border-white/10 text-slate-400 bg-white/5" },
    { name: "Initial Access", color: "border-cyan-500/30 text-cyan-400 bg-cyan-950/10" },
    { name: "Execution", color: "border-blue-500/30 text-blue-400 bg-blue-950/10" },
    { name: "Credential Access", color: "border-indigo-500/30 text-indigo-400 bg-indigo-950/10" },
    { name: "Command and Control", color: "border-purple-500/30 text-purple-400 bg-purple-950/10" },
    { name: "Impact", color: "border-rose-500/30 text-rose-400 bg-rose-950/10" }
  ];

  const getTacticsMap = () => {
    const map: Record<string, MITRETechnique[]> = {};
    tactics.forEach(t => {
      map[t.name] = techniques.filter(tech => tech.tactic === t.name);
    });
    // Let's also fallback and place "Exfiltration" inside "Impact" or make a combined column if needed
    // In our types, we have Exfiltration. Let's merge Exfiltration and Impact for layout density
    const exfilTechs = techniques.filter(tech => tech.tactic === "Exfiltration" as any);
    if (map["Impact"]) {
      map["Impact"] = [...map["Impact"], ...exfilTechs];
    }
    return map;
  };

  const grouped = getTacticsMap();

  return (
    <div className="bg-[#0d1117] border border-white/5 rounded-xl p-5 shadow-2xl relative overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100 font-mono uppercase tracking-wider">MITRE ATT&CK Mapping Matrix</h3>
        </div>
        <div className="flex items-center gap-4 text-[10px] font-mono text-white/40">
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded bg-[#05070a] border border-white/5 inline-block"></span>
            Inactive
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded bg-rose-500/20 border border-rose-500 inline-block animate-pulse"></span>
            Active Detection
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2.5">
        {tactics.map(tactic => (
          <div key={tactic.name} className="flex flex-col gap-2">
            {/* Column Header */}
            <div className={`p-2 rounded-lg border text-center ${tactic.color}`}>
              <p className="text-[10px] font-bold font-mono uppercase tracking-wider truncate">
                {tactic.name}
              </p>
            </div>

            {/* Techniques */}
            <div className="flex flex-col gap-1.5 flex-1 min-h-[150px]">
              {grouped[tactic.name]?.map(tech => (
                <div
                  key={tech.id}
                  onMouseEnter={() => setHoveredTech(tech.id)}
                  onMouseLeave={() => setHoveredTech(null)}
                  onClick={() => onSelectTechnique(tech)}
                  className={`group relative p-2.5 rounded-lg border transition-all cursor-pointer select-none flex flex-col justify-between h-[85px] ${
                    tech.triggered
                      ? "bg-rose-500/10 border-rose-500 text-rose-200 shadow-[0_0_10px_rgba(239,68,68,0.15)] hover:bg-rose-500/20"
                      : "bg-[#05070a]/40 border-white/5 text-white/40 hover:border-white/10 hover:bg-white/5"
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] font-bold font-mono text-white/30 group-hover:text-white/50">
                        {tech.id}
                      </span>
                      {tech.triggered && (
                        <span className="flex h-1.5 w-1.5 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-rose-500"></span>
                        </span>
                      )}
                    </div>
                    <p className={`text-[11px] font-semibold leading-snug mt-1 font-sans line-clamp-2 ${
                      tech.triggered ? "text-rose-200 font-bold" : "text-slate-300"
                    }`}>
                      {tech.name}
                    </p>
                  </div>

                  <div className="flex items-center justify-between text-[9px] mt-1">
                    {tech.triggered ? (
                      <span className="bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded border border-rose-500/30 font-mono font-bold">
                        {tech.associatedLogsCount} {tech.associatedLogsCount === 1 ? "log" : "logs"}
                      </span>
                    ) : (
                      <span className="text-white/20 group-hover:text-white/30 font-mono">dormant</span>
                    )}
                    <Eye className="w-3 h-3 opacity-0 group-hover:opacity-100 text-slate-400 transition-opacity" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
