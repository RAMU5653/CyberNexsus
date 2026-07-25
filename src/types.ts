export interface LogEvent {
  id: string;
  timestamp: string;
  host: "Windows-VM" | "Kali-VM" | "Network-Sensor";
  source: "Sysmon" | "PowerShell" | "auth.log" | "syslog" | "Suricata" | "Zeek";
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  mitreId?: string;
  mitreName?: string;
  category: string;
  details: {
    srcIp?: string;
    dstIp?: string;
    dstPort?: number;
    user?: string;
    process?: string;
    command?: string;
    filePath?: string;
    riskScoreContribution?: number;
    [key: string]: any;
  };
}

export interface MITRETechnique {
  id: string;
  name: string;
  tactic: "Reconnaissance" | "Initial Access" | "Execution" | "Persistence" | "Lateral Movement" | "Exfiltration";
  description: string;
  triggered: boolean;
  associatedLogsCount: number;
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  icon: string;
  targetVM: string;
  impactRisk: number;
  steps: string[];
  logs: Omit<LogEvent, "id" | "timestamp">[];
}

export interface IncidentReport {
  title: string;
  summary: string;
  riskScore: number;
  severity: "low" | "medium" | "high" | "critical";
  timeline: { time: string; event: string; host: string }[];
  mitreMapping: { techniqueId: string; techniqueName: string; tactic: string }[];
  technicalDetails: string;
  remediationSteps: string[];
}
