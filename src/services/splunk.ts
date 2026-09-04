export async function getLiveLogs() {
  const res = await fetch("/api/splunk/logs");

  if (!res.ok) {
    throw new Error("Unable to load Splunk logs");
  }

  const data = await res.json();

  const riskScoreHeader = res.headers.get("X-SOC-Risk-Score");

  const logs = data.map((item: any, index: number) => {
    const e = item.result;

    let severity = "low";

    try {
      const raw = JSON.parse(e._raw);

      switch (raw.event_type) {
        case "alert":
          severity = "critical";
          break;
        case "tls":
          severity = "medium";
          break;
        case "flow":
        case "dns":
        case "mdns":
        case "stats":
        default:
          severity = "low";
      }
    } catch {
      severity = "low";
    }

    return {
      id: `${index}`,
      timestamp: e._time,
      host: e.host,
      source: e.sourcetype,
      sourcetype: e.sourcetype,
      index: e.index,
      eventCode: Number(e.EventCode || e.EventID || e.event_id || 0) || undefined,
      severity,
      message: e._raw,
      category: e.index,
      details: e,
    };
  });

  return {
    logs,
    riskScore: riskScoreHeader !== null ? Number(riskScoreHeader) : 0,
  };
}
