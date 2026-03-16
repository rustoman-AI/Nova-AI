import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SocAlert {
    id: string;
    timestamp: string;
    severity: string;
    source: string;
    message: string;
}

interface SocOverview {
    threat_level: string;
    threat_score: number;
    active_alerts: number;
    critical_alerts: number;
    high_alerts: number;
    medium_alerts: number;
    low_alerts: number;
    pipeline_health: number;
    sbom_coverage: number;
    compliance_score: number;
    container_events_sec: number;
    cves_total: number;
    cves_critical: number;
    kev_matches: number;
    mttr_hours: number;
    swarm_bots_active: number;
    recent_alerts: SocAlert[];
}

const THREAT_COLORS: Record<string, string> = {
    CRITICAL: "#ff7b72",
    HIGH: "#ffa657",
    MEDIUM: "#d2a8ff",
    LOW: "#3fb950",
};

const SEV_COLORS: Record<string, string> = {
    CRITICAL: "#ff7b72",
    HIGH: "#ffa657",
    MEDIUM: "#d2a8ff",
    LOW: "#58a6ff",
};

const SOURCE_ICONS: Record<string, string> = {
    RUNTIME: "🐳",
    THREAT_INTEL: "🌐",
    POSTURE: "📈",
    PIPELINE: "⚙️",
    SBOM: "📦",
};

const MOCK: SocOverview = {
    threat_level: "HIGH", threat_score: 68.5, active_alerts: 34, critical_alerts: 4, high_alerts: 9,
    medium_alerts: 14, low_alerts: 7, pipeline_health: 94.2, sbom_coverage: 93.1, compliance_score: 89.4,
    container_events_sec: 22, cves_total: 28, cves_critical: 4, kev_matches: 6, mttr_hours: 38.5, swarm_bots_active: 14,
    recent_alerts: [
        { id: "a1", timestamp: "21:54:42Z", severity: "CRITICAL", source: "RUNTIME", message: "ptrace(PTRACE_ATTACH) syscall intercepted in container auth-svc-9d1e" },
        { id: "a2", timestamp: "21:49:18Z", severity: "HIGH", source: "THREAT_INTEL", message: "CVE-2024-3094 (XZ Utils) matched in SBOM component xz-utils:5.6.0" },
        { id: "a3", timestamp: "21:44:03Z", severity: "CRITICAL", source: "RUNTIME", message: "Data exfiltration: 14MB uploaded to external S3 bucket from api-gateway" },
        { id: "a4", timestamp: "21:38:55Z", severity: "HIGH", source: "POSTURE", message: "Compliance score dropped below 85% threshold" },
        { id: "a5", timestamp: "21:33:22Z", severity: "MEDIUM", source: "RUNTIME", message: "DNS query to suspicious domain crypto-miner-pool.xyz from worker-queue" },
        { id: "a6", timestamp: "21:28:11Z", severity: "HIGH", source: "THREAT_INTEL", message: "CISA KEV alert: CVE-2024-27198 actively exploited in TeamCity" },
        { id: "a7", timestamp: "21:22:47Z", severity: "CRITICAL", source: "PIPELINE", message: "Build provenance attestation failed for artifact sha256:a3b8d1" },
        { id: "a8", timestamp: "21:17:09Z", severity: "MEDIUM", source: "SBOM", message: "3 new transitive dependencies detected without license metadata" },
    ]
};

export default function SocCommandCenter() {
    const [data, setData] = useState<SocOverview | null>(null);

    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

    useEffect(() => {
        (async () => {
            try {
                if (isTauri) {
                    setData(await invoke<SocOverview>("engine_get_soc_overview"));
                } else {
                    setData(MOCK);
                }
            } catch {
                setData(MOCK);
            }
        })();
    }, [isTauri]);

    if (!data) return <div style={{ padding: 40, color: "#8b949e" }}>Initializing SOC Command Center...</div>;

    const ringPct = data.threat_score;
    const ringColor = THREAT_COLORS[data.threat_level];

    return (
        <div style={{ padding: "25px", height: "100%", overflow: "auto", color: "#c9d1d9" }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "25px" }}>
                <div>
                    <h2 style={{ margin: "0 0 5px", fontSize: "26px", color: "#e6edf3" }}>🛡️ SOC Command Center</h2>
                    <p style={{ color: "#8b949e", margin: 0 }}>Unified security operations overview — all threat vectors in one view.</p>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", background: `${ringColor}15`, border: `1px solid ${ringColor}44`, borderRadius: "8px", padding: "8px 16px" }}>
                    <div style={{ width: "12px", height: "12px", borderRadius: "50%", background: ringColor, animation: "pulse 2s infinite" }} />
                    <span style={{ fontSize: "14px", fontWeight: "bold", color: ringColor }}>THREAT LEVEL: {data.threat_level}</span>
                </div>
            </div>

            {/* Main Grid: Threat Ring + Metrics */}
            <div style={{ display: "flex", gap: "20px", marginBottom: "20px" }}>
                {/* Threat Ring */}
                <div style={{ width: "280px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "12px", padding: "25px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                    <div style={{
                        width: "180px", height: "180px", borderRadius: "50%",
                        background: `conic-gradient(${ringColor} 0deg, ${ringColor} ${ringPct * 3.6}deg, #21262d ${ringPct * 3.6}deg, #21262d 360deg)`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        animation: "glow 3s ease-in-out infinite",
                        boxShadow: `0 0 30px ${ringColor}33`,
                    }}>
                        <div style={{ width: "140px", height: "140px", borderRadius: "50%", background: "#0d1117", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                            <div style={{ fontSize: "36px", fontWeight: "bold", color: ringColor }}>{data.threat_score}</div>
                            <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase" }}>Threat Score</div>
                        </div>
                    </div>
                    <div style={{ marginTop: "15px", display: "flex", gap: "12px" }}>
                        {[["CRITICAL", data.critical_alerts], ["HIGH", data.high_alerts], ["MEDIUM", data.medium_alerts], ["LOW", data.low_alerts]].map(([sev, count]) => (
                            <div key={sev as string} style={{ textAlign: "center" }}>
                                <div style={{ fontSize: "16px", fontWeight: "bold", color: SEV_COLORS[sev as string] }}>{count as number}</div>
                                <div style={{ fontSize: "8px", color: SEV_COLORS[sev as string], textTransform: "uppercase", opacity: 0.7 }}>{sev as string}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Metric Tiles Grid */}
                <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px" }}>
                    {[
                        { label: "Active Alerts", value: data.active_alerts, icon: "🔔", color: "#ffa657" },
                        { label: "Pipeline Health", value: `${data.pipeline_health}%`, icon: "⚙️", color: "#3fb950" },
                        { label: "SBOM Coverage", value: `${data.sbom_coverage}%`, icon: "📦", color: "#58a6ff" },
                        { label: "Compliance", value: `${data.compliance_score}%`, icon: "✅", color: "#3fb950" },
                        { label: "Container Events/s", value: data.container_events_sec, icon: "🐳", color: "#d2a8ff" },
                        { label: "Total CVEs", value: data.cves_total, icon: "🔥", color: "#ff7b72" },
                        { label: "KEV Matches", value: data.kev_matches, icon: "🎯", color: "#f85149" },
                        { label: "Swarm Bots", value: data.swarm_bots_active, icon: "🤖", color: "#79c0ff" },
                    ].map(tile => (
                        <div key={tile.label} style={{ background: "#0d1117", border: `1px solid ${tile.color}22`, borderRadius: "10px", padding: "16px", display: "flex", flexDirection: "column", justifyContent: "space-between", transition: "all 0.2s" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontSize: "20px" }}>{tile.icon}</span>
                                <span style={{ fontSize: "10px", color: "#6e7681", textTransform: "uppercase" }}>{tile.label}</span>
                            </div>
                            <div style={{ fontSize: "28px", fontWeight: "bold", color: tile.color, marginTop: "8px" }}>{tile.value}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Bottom Row: MTTR + Alert Ticker */}
            <div style={{ display: "flex", gap: "20px" }}>
                {/* MTTR & Quick Stats */}
                <div style={{ width: "280px", display: "flex", flexDirection: "column", gap: "12px" }}>
                    <div style={{ background: "#0d1117", border: "1px solid #d2a8ff22", borderRadius: "10px", padding: "16px", textAlign: "center" }}>
                        <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase", marginBottom: "6px" }}>Mean Time to Remediate</div>
                        <div style={{ fontSize: "32px", fontWeight: "bold", color: "#d2a8ff" }}>{data.mttr_hours}h</div>
                    </div>
                    <div style={{ background: "#0d1117", border: "1px solid #f8514922", borderRadius: "10px", padding: "16px", textAlign: "center" }}>
                        <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase", marginBottom: "6px" }}>Critical CVEs</div>
                        <div style={{ fontSize: "32px", fontWeight: "bold", color: "#f85149" }}>{data.cves_critical}</div>
                    </div>
                </div>

                {/* Live Alert Ticker */}
                <div style={{ flex: 1, background: "#0d1117", border: "1px solid #30363d", borderRadius: "10px", overflow: "hidden" }}>
                    <div style={{ padding: "12px 16px", borderBottom: "1px solid #21262d", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "12px", fontWeight: "bold", color: "#8b949e", textTransform: "uppercase" }}>🔔 Live Alert Feed</span>
                        <span style={{ fontSize: "11px", color: "#ffa657" }}>{data.active_alerts} active</span>
                    </div>
                    <div style={{ maxHeight: "200px", overflowY: "auto" }}>
                        {data.recent_alerts.map((alert, idx) => (
                            <div key={alert.id} style={{ padding: "10px 16px", borderBottom: "1px solid #21262d", display: "flex", alignItems: "flex-start", gap: "10px", animation: idx < 3 ? "fadeIn 0.5s ease" : undefined }}>
                                <span style={{ fontSize: "14px", flexShrink: 0 }}>{SOURCE_ICONS[alert.source] || "📋"}</span>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "3px" }}>
                                        <span style={{ fontSize: "10px", fontWeight: "bold", color: SEV_COLORS[alert.severity], border: `1px solid ${SEV_COLORS[alert.severity]}44`, padding: "1px 6px", borderRadius: "3px" }}>{alert.severity}</span>
                                        <span style={{ fontSize: "10px", color: "#6e7681" }}>{alert.source}</span>
                                        <span style={{ fontSize: "10px", color: "#6e7681", marginLeft: "auto", fontFamily: "monospace" }}>{alert.timestamp}</span>
                                    </div>
                                    <div style={{ fontSize: "12px", color: "#c9d1d9", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{alert.message}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
                @keyframes glow { 0%, 100% { box-shadow: 0 0 30px ${ringColor}33; } 50% { box-shadow: 0 0 50px ${ringColor}55; } }
                @keyframes fadeIn { from { opacity: 0; background: #1f6feb15; } to { opacity: 1; background: transparent; } }
            `}</style>
        </div>
    );
}
