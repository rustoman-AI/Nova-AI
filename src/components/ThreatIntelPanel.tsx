import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ThreatCorrelation {
    id: string;
    cve_id: string;
    title: string;
    cvss_score: number;
    severity: string;
    affected_component: string;
    affected_version: string;
    kev_listed: boolean;
    mitre_tactic: string;
    mitre_technique: string;
    mitre_technique_id: string;
    description: string;
    published: string;
    references: string[];
}

const KILL_CHAIN: string[] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
];

const SEVERITY_COLORS: Record<string, string> = {
    CRITICAL: "#ff7b72",
    HIGH: "#ffa657",
    MEDIUM: "#d2a8ff",
    LOW: "#58a6ff",
};

function cvssColor(score: number): string {
    if (score >= 9.0) return "#ff7b72";
    if (score >= 7.0) return "#ffa657";
    if (score >= 4.0) return "#d2a8ff";
    return "#58a6ff";
}

const MOCK_DATA: ThreatCorrelation[] = [
    { id: "tc-001", cve_id: "CVE-2024-3094", title: "XZ Utils Backdoor — Supply-Chain Compromise", cvss_score: 10.0, severity: "CRITICAL", affected_component: "xz-utils", affected_version: "5.6.0–5.6.1", kev_listed: true, mitre_tactic: "Initial Access", mitre_technique: "Supply Chain Compromise", mitre_technique_id: "T1195.002", description: "Malicious code was discovered in the upstream xz/liblzma tarballs, enabling remote code execution through sshd via systemd.", published: "2024-03-29", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"] },
    { id: "tc-002", cve_id: "CVE-2024-1086", title: "Linux Kernel nf_tables Use-After-Free LPE", cvss_score: 7.8, severity: "HIGH", affected_component: "linux-kernel", affected_version: "3.15–6.8-rc1", kev_listed: true, mitre_tactic: "Privilege Escalation", mitre_technique: "Exploitation for Privilege Escalation", mitre_technique_id: "T1068", description: "A use-after-free vulnerability in the nf_tables component allows local privilege escalation to root.", published: "2024-01-31", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1086"] },
    { id: "tc-003", cve_id: "CVE-2023-44487", title: "HTTP/2 Rapid Reset DDoS Attack", cvss_score: 7.5, severity: "HIGH", affected_component: "nginx", affected_version: "< 1.25.3", kev_listed: true, mitre_tactic: "Impact", mitre_technique: "Endpoint Denial of Service", mitre_technique_id: "T1499.003", description: "The HTTP/2 protocol allows DoS because request cancellation can reset many streams quickly.", published: "2023-10-10", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"] },
    { id: "tc-004", cve_id: "CVE-2024-21626", title: "runc Container Escape via /proc/self/fd Leak", cvss_score: 8.6, severity: "HIGH", affected_component: "runc", affected_version: "< 1.1.12", kev_listed: false, mitre_tactic: "Defense Evasion", mitre_technique: "Escape to Host", mitre_technique_id: "T1611", description: "runc leaks an internal file descriptor to the container init process, allowing container escape.", published: "2024-01-31", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21626"] },
    { id: "tc-005", cve_id: "CVE-2024-27198", title: "JetBrains TeamCity Authentication Bypass", cvss_score: 9.8, severity: "CRITICAL", affected_component: "teamcity-server", affected_version: "< 2023.11.4", kev_listed: true, mitre_tactic: "Initial Access", mitre_technique: "Exploit Public-Facing Application", mitre_technique_id: "T1190", description: "Authentication bypass allows unauthenticated attackers to perform admin actions including RCE.", published: "2024-03-04", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"] },
    { id: "tc-006", cve_id: "CVE-2023-38545", title: "curl SOCKS5 Heap Buffer Overflow", cvss_score: 9.8, severity: "CRITICAL", affected_component: "curl", affected_version: "7.69.0–8.3.0", kev_listed: false, mitre_tactic: "Execution", mitre_technique: "Exploitation for Client Execution", mitre_technique_id: "T1203", description: "A heap-based buffer overflow in the SOCKS5 proxy handshake could allow RCE.", published: "2023-10-11", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-38545"] },
    { id: "tc-007", cve_id: "CVE-2024-4577", title: "PHP-CGI Argument Injection on Windows", cvss_score: 9.8, severity: "CRITICAL", affected_component: "php", affected_version: "< 8.3.8", kev_listed: true, mitre_tactic: "Execution", mitre_technique: "Command and Scripting Interpreter", mitre_technique_id: "T1059.004", description: "PHP-CGI on Windows allows argument injection bypassing CVE-2012-1823 protections.", published: "2024-06-06", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"] },
    { id: "tc-008", cve_id: "CVE-2023-46604", title: "Apache ActiveMQ RCE via ClassPathXmlApplicationContext", cvss_score: 10.0, severity: "CRITICAL", affected_component: "activemq", affected_version: "< 5.18.3", kev_listed: true, mitre_tactic: "Execution", mitre_technique: "Exploitation of Remote Services", mitre_technique_id: "T1210", description: "Remote Code Execution via OpenWire protocol through crafted class loading.", published: "2023-10-27", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"] },
];

export default function ThreatIntelPanel() {
    const [threats, setThreats] = useState<ThreatCorrelation[]>([]);
    const [selected, setSelected] = useState<ThreatCorrelation | null>(null);
    const [loading, setLoading] = useState(true);

    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

    useEffect(() => {
        (async () => {
            try {
                if (isTauri) {
                    const data = await invoke<ThreatCorrelation[]>("engine_get_threat_correlations");
                    setThreats(data);
                } else {
                    setThreats(MOCK_DATA);
                }
            } catch {
                setThreats(MOCK_DATA);
            }
            setLoading(false);
        })();
    }, [isTauri]);

    useEffect(() => {
        if (threats.length > 0 && !selected) setSelected(threats[0]);
    }, [threats, selected]);

    const kevCount = threats.filter(t => t.kev_listed).length;
    const critCount = threats.filter(t => t.severity === "CRITICAL").length;
    const avgCvss = threats.length ? (threats.reduce((s, t) => s + t.cvss_score, 0) / threats.length).toFixed(1) : "0";

    if (loading) return <div style={{ padding: 40, color: "#8b949e" }}>Loading threat intelligence feeds...</div>;

    return (
        <div style={{ padding: "25px", height: "100%", display: "flex", flexDirection: "column", color: "#c9d1d9" }}>
            {/* Header */}
            <div style={{ marginBottom: "20px" }}>
                <h2 style={{ margin: "0 0 5px", fontSize: "24px", color: "#58a6ff" }}>🌐 Threat Intelligence Correlations</h2>
                <p style={{ color: "#8b949e", margin: 0 }}>SBOM components cross-referenced against NVD, MITRE ATT&CK, and CISA KEV feeds.</p>
            </div>

            {/* Summary Cards */}
            <div style={{ display: "flex", gap: "12px", marginBottom: "20px" }}>
                <div style={{ flex: 1, background: "#0d1117", border: "1px solid #ff7b7233", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                    <div style={{ fontSize: "22px", fontWeight: "bold", color: "#ff7b72" }}>{critCount}</div>
                    <div style={{ fontSize: "10px", color: "#ff7b72", textTransform: "uppercase", opacity: 0.7 }}>Critical Threats</div>
                </div>
                <div style={{ flex: 1, background: "#0d1117", border: "1px solid #da363333", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                    <div style={{ fontSize: "22px", fontWeight: "bold", color: "#f85149", animation: "pulse 2s infinite" }}>{kevCount}</div>
                    <div style={{ fontSize: "10px", color: "#f85149", textTransform: "uppercase", opacity: 0.7 }}>🔴 CISA KEV Listed</div>
                </div>
                <div style={{ flex: 1, background: "#0d1117", border: "1px solid #ffa65733", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                    <div style={{ fontSize: "22px", fontWeight: "bold", color: "#ffa657" }}>{avgCvss}</div>
                    <div style={{ fontSize: "10px", color: "#ffa657", textTransform: "uppercase", opacity: 0.7 }}>Avg CVSS Score</div>
                </div>
                <div style={{ flex: 1, background: "#0d1117", border: "1px solid #58a6ff33", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                    <div style={{ fontSize: "22px", fontWeight: "bold", color: "#58a6ff" }}>{threats.length}</div>
                    <div style={{ fontSize: "10px", color: "#58a6ff", textTransform: "uppercase", opacity: 0.7 }}>Correlated Threats</div>
                </div>
            </div>

            {/* Split View */}
            <div style={{ flex: 1, display: "flex", gap: "15px", minHeight: 0 }}>
                {/* Left — Threat List */}
                <div style={{ width: "420px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "8px" }}>
                    {threats.sort((a, b) => b.cvss_score - a.cvss_score).map(t => (
                        <div
                            key={t.id}
                            onClick={() => setSelected(t)}
                            style={{
                                background: selected?.id === t.id ? "#161b22" : "#0d1117",
                                border: selected?.id === t.id ? "1px solid #58a6ff" : "1px solid #30363d",
                                borderRadius: "8px", padding: "12px", cursor: "pointer", transition: "all 0.2s",
                                borderLeft: `4px solid ${SEVERITY_COLORS[t.severity]}`
                            }}
                        >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                                <span style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: "bold", color: cvssColor(t.cvss_score) }}>{t.cve_id}</span>
                                <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                    {t.kev_listed && <span style={{ fontSize: "9px", background: "#da3633", color: "white", padding: "2px 6px", borderRadius: "4px", fontWeight: "bold", animation: "pulse 2s infinite" }}>KEV</span>}
                                    <span style={{ fontSize: "12px", fontWeight: "bold", background: `${cvssColor(t.cvss_score)}22`, color: cvssColor(t.cvss_score), padding: "2px 8px", borderRadius: "4px" }}>{t.cvss_score}</span>
                                </div>
                            </div>
                            <div style={{ fontSize: "13px", color: "#e6edf3", lineHeight: 1.3 }}>{t.title}</div>
                            <div style={{ fontSize: "11px", color: "#8b949e", marginTop: "4px" }}>
                                <span style={{ color: "#d2a8ff" }}>{t.affected_component}</span> {t.affected_version}
                            </div>
                        </div>
                    ))}
                </div>

                {/* Right — Detail + ATT&CK Kill Chain */}
                {selected && (
                    <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "15px" }}>
                        {/* Detail Card */}
                        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "15px" }}>
                                <div>
                                    <h3 style={{ margin: "0 0 4px", fontSize: "18px", color: "#e6edf3" }}>{selected.title}</h3>
                                    <span style={{ fontFamily: "monospace", fontSize: "14px", color: cvssColor(selected.cvss_score), fontWeight: "bold" }}>{selected.cve_id}</span>
                                </div>
                                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "6px" }}>
                                    <div style={{ fontSize: "28px", fontWeight: "bold", color: cvssColor(selected.cvss_score) }}>{selected.cvss_score}</div>
                                    <span style={{ fontSize: "10px", color: SEVERITY_COLORS[selected.severity], textTransform: "uppercase", fontWeight: "bold" }}>CVSS 3.1 — {selected.severity}</span>
                                </div>
                            </div>
                            <p style={{ color: "#8b949e", fontSize: "13px", lineHeight: 1.6, margin: "0 0 15px" }}>{selected.description}</p>
                            <div style={{ display: "flex", gap: "20px", fontSize: "12px" }}>
                                <div><span style={{ color: "#8b949e" }}>Component:</span> <span style={{ color: "#d2a8ff", fontWeight: "bold" }}>{selected.affected_component}</span></div>
                                <div><span style={{ color: "#8b949e" }}>Version:</span> <span style={{ color: "#e6edf3" }}>{selected.affected_version}</span></div>
                                <div><span style={{ color: "#8b949e" }}>Published:</span> <span style={{ color: "#e6edf3" }}>{selected.published}</span></div>
                                {selected.kev_listed && <div style={{ color: "#f85149", fontWeight: "bold", animation: "pulse 2s infinite" }}>🔴 Actively Exploited (CISA KEV)</div>}
                            </div>
                        </div>

                        {/* MITRE ATT&CK Kill Chain */}
                        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "20px" }}>
                            <h4 style={{ margin: "0 0 15px", fontSize: "14px", color: "#8b949e", textTransform: "uppercase" }}>MITRE ATT&CK Kill Chain Mapping</h4>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                {KILL_CHAIN.map(phase => {
                                    const isActive = selected.mitre_tactic === phase;
                                    return (
                                        <div key={phase} style={{
                                            padding: "8px 12px", borderRadius: "6px", fontSize: "11px", fontWeight: "bold",
                                            background: isActive ? "#1f6feb" : "#161b22",
                                            color: isActive ? "white" : "#6e7681",
                                            border: isActive ? "1px solid #58a6ff" : "1px solid #21262d",
                                            position: "relative",
                                            transition: "all 0.3s",
                                        }}>
                                            {phase}
                                            {isActive && <div style={{ position: "absolute", bottom: -8, left: "50%", transform: "translateX(-50%)", fontSize: "8px", color: "#58a6ff" }}>▼</div>}
                                        </div>
                                    );
                                })}
                            </div>
                            <div style={{ marginTop: "15px", background: "#161b22", borderRadius: "6px", padding: "12px", border: "1px solid #21262d" }}>
                                <div style={{ fontSize: "12px", color: "#58a6ff", fontWeight: "bold", marginBottom: "4px" }}>{selected.mitre_technique_id} — {selected.mitre_technique}</div>
                                <div style={{ fontSize: "11px", color: "#8b949e" }}>Tactic: {selected.mitre_tactic}</div>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            <style>{`@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }`}</style>
        </div>
    );
}
