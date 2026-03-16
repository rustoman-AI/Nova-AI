import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface TrivyVuln { vuln_id: string; pkg_name: string; installed_version: string; fixed_version: string; severity: string; title: string; primary_url: string; }
interface TrivyMisconf { id: string; title: string; severity: string; message: string; resolution: string; }
interface TrivySecret { rule_id: string; category: string; title: string; severity: string; match_str: string; }
interface TrivySummary { total_vulns: number; critical: number; high: number; medium: number; low: number; unknown: number; total_misconf: number; total_secrets: number; vex_filtered: number; }
interface TrivyResult { success: boolean; scan_type: string; target: string; summary: TrivySummary; vulnerabilities: TrivyVuln[]; misconfigurations: TrivyMisconf[]; secrets: TrivySecret[]; error: string | null; duration_ms: number; trivy_version: string; vex_applied: boolean; vex_path: string | null; }
interface TrivyInfo { installed: boolean; version: string; scan_types: string[]; severities: string[]; vex_formats: string[]; }

const SEV: Record<string, { color: string; bg: string }> = {
    CRITICAL: { color: "#ff4d4f", bg: "#ff4d4f18" },
    HIGH: { color: "#fa8c16", bg: "#fa8c1618" },
    MEDIUM: { color: "#fadb14", bg: "#fadb1418" },
    LOW: { color: "#52c41a", bg: "#52c41a18" },
    UNKNOWN: { color: "#8c8c8c", bg: "#8c8c8c18" },
};

const SCAN_ICONS: Record<string, string> = { image: "🐳", fs: "📂", repo: "📦", config: "⚙️", sbom: "📋", rootfs: "🗂️", vm: "💻" };

export default function TrivyScanPanel() {
    const [info, setInfo] = useState<TrivyInfo | null>(null);
    const [target, setTarget] = useState("");
    const [scanType, setScanType] = useState("fs");
    const [severity, setSeverity] = useState("CRITICAL,HIGH,MEDIUM,LOW");
    const [skipDb, setSkipDb] = useState(false);
    const [vexPath, setVexPath] = useState("");
    const [ignoreUnfixed, setIgnoreUnfixed] = useState(false);
    const [result, setResult] = useState<TrivyResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [vexGenerating, setVexGenerating] = useState(false);
    const [tab, setTab] = useState<"vulns" | "misconf" | "secrets">("vulns");

    useEffect(() => { invoke<TrivyInfo>("trivy_check").then(setInfo); }, []);

    const handleScan = useCallback(async () => {
        if (!target.trim()) return;
        setLoading(true);
        setResult(null);
        try {
            const res = await invoke<TrivyResult>("trivy_scan", {
                request: { target, scan_type: scanType, severity: severity || null, skip_db_update: skipDb, format: null, vex_path: vexPath || null, ignore_unfixed: ignoreUnfixed },
            });
            setResult(res);
            if (res.misconfigurations.length > 0 && res.vulnerabilities.length === 0) setTab("misconf");
            else if (res.secrets.length > 0 && res.vulnerabilities.length === 0) setTab("secrets");
            else setTab("vulns");
        } catch (e) { setResult({ success: false, scan_type: scanType, target, summary: { total_vulns: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total_misconf: 0, total_secrets: 0, vex_filtered: 0 }, vulnerabilities: [], misconfigurations: [], secrets: [], error: String(e), duration_ms: 0, trivy_version: "", vex_applied: false, vex_path: null }); }
        setLoading(false);
    }, [target, scanType, severity, skipDb, vexPath, ignoreUnfixed]);

    const handleGenerateVex = useCallback(async () => {
        if (!target.trim()) return;
        setVexGenerating(true);
        try {
            const res = await invoke<{ path: string; statements: number; message: string }>("trivy_generate_vex", {
                target, scanType, outputPath: "./vex-template.json",
            });
            setVexPath(res.path);
            alert(`✅ VEX template created: ${res.statements} statements\n\n${res.message}`);
        } catch (e) { alert(`VEX generation failed: ${e}`); }
        setVexGenerating(false);
    }, [target, scanType]);

    const s = result?.summary;

    return (
        <div style={{ padding: "24px", maxWidth: 1200, margin: "0 auto" }}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
                <h2 style={{ margin: 0 }}>🔍 Trivy Scanner</h2>
                {info && (
                    <span className="tv-badge" style={{ background: info.installed ? "#52c41a22" : "#ff4d4f22", color: info.installed ? "#52c41a" : "#ff4d4f" }}>
                        {info.installed ? `✓ ${info.version}` : "✗ Not installed"}
                    </span>
                )}
            </div>

            {/* Scan form */}
            <div className="tv-form">
                <div className="tv-form-row">
                    <div className="tv-form-group" style={{ flex: 2 }}>
                        <label className="tv-label">Target</label>
                        <input className="tv-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="alpine:3.19 or /path/to/project or https://github.com/..." onKeyDown={e => e.key === "Enter" && handleScan()} />
                    </div>
                    <div className="tv-form-group">
                        <label className="tv-label">Scan Type</label>
                        <select className="tv-select" value={scanType} onChange={e => setScanType(e.target.value)}>
                            {(info?.scan_types || ["image", "fs", "repo", "config", "sbom"]).map(t => (
                                <option key={t} value={t}>{SCAN_ICONS[t] || "📋"} {t}</option>
                            ))}
                        </select>
                    </div>
                    <div className="tv-form-group">
                        <label className="tv-label">Severity</label>
                        <select className="tv-select" value={severity} onChange={e => setSeverity(e.target.value)}>
                            <option value="CRITICAL,HIGH,MEDIUM,LOW">All</option>
                            <option value="CRITICAL,HIGH">Critical+High</option>
                            <option value="CRITICAL">Critical only</option>
                        </select>
                    </div>
                </div>
                {/* VEX row */}
                <div className="tv-form-row" style={{ marginTop: 8 }}>
                    <div className="tv-form-group" style={{ flex: 2 }}>
                        <label className="tv-label">📄 VEX Document (OpenVEX / CycloneDX VEX / CSAF)</label>
                        <div style={{ display: "flex", gap: 6 }}>
                            <input className="tv-input" style={{ flex: 1 }} value={vexPath} onChange={e => setVexPath(e.target.value)} placeholder="path/to/vex.json — filter false positives" />
                            <button onClick={handleGenerateVex} disabled={vexGenerating || !target.trim()} className="tv-btn" title="Generate VEX template from current target">
                                {vexGenerating ? "⏳" : "📝"} Generate VEX
                            </button>
                        </div>
                    </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8 }}>
                    <button onClick={handleScan} disabled={loading || !target.trim()} className="tv-btn tv-btn-primary">
                        {loading ? "⏳ Scanning..." : `🔍 Scan ${scanType}`}
                    </button>
                    <label style={{ fontSize: 12, color: "#8c8c8c", display: "flex", alignItems: "center", gap: 4 }}>
                        <input type="checkbox" checked={skipDb} onChange={e => setSkipDb(e.target.checked)} /> Skip DB update
                    </label>
                    <label style={{ fontSize: 12, color: "#8c8c8c", display: "flex", alignItems: "center", gap: 4 }}>
                        <input type="checkbox" checked={ignoreUnfixed} onChange={e => setIgnoreUnfixed(e.target.checked)} /> Ignore unfixed
                    </label>
                    {result?.vex_applied && <span style={{ fontSize: 11, color: "#722ed1", background: "#722ed118", padding: "2px 8px", borderRadius: 8 }}>📄 VEX applied</span>}
                    {result && <span style={{ fontSize: 12, color: "#8c8c8c" }}>⏱️ {result.duration_ms}ms</span>}
                </div>
            </div>

            {/* Error */}
            {result?.error && <div className="tv-error">{result.error}</div>}

            {/* Summary cards */}
            {result?.success && s && (
                <div className="tv-summary-row">
                    <div className="tv-card" style={{ borderColor: "#ff4d4f" }}><div className="tv-card-label">Critical</div><div className="tv-card-val" style={{ color: "#ff4d4f" }}>{s.critical}</div></div>
                    <div className="tv-card" style={{ borderColor: "#fa8c16" }}><div className="tv-card-label">High</div><div className="tv-card-val" style={{ color: "#fa8c16" }}>{s.high}</div></div>
                    <div className="tv-card" style={{ borderColor: "#fadb14" }}><div className="tv-card-label">Medium</div><div className="tv-card-val" style={{ color: "#fadb14" }}>{s.medium}</div></div>
                    <div className="tv-card" style={{ borderColor: "#52c41a" }}><div className="tv-card-label">Low</div><div className="tv-card-val" style={{ color: "#52c41a" }}>{s.low}</div></div>
                    <div className="tv-card"><div className="tv-card-label">Misconfig</div><div className="tv-card-val" style={{ color: "#722ed1" }}>{s.total_misconf}</div></div>
                    <div className="tv-card"><div className="tv-card-label">Secrets</div><div className="tv-card-val" style={{ color: "#eb2f96" }}>{s.total_secrets}</div></div>
                </div>
            )}

            {/* Tabs */}
            {result?.success && (
                <>
                    <div className="tv-tabs">
                        <button className={`tv-tab ${tab === "vulns" ? "active" : ""}`} onClick={() => setTab("vulns")}>
                            🛡️ Vulnerabilities ({result.vulnerabilities.length})
                        </button>
                        <button className={`tv-tab ${tab === "misconf" ? "active" : ""}`} onClick={() => setTab("misconf")}>
                            ⚙️ Misconfigurations ({result.misconfigurations.length})
                        </button>
                        <button className={`tv-tab ${tab === "secrets" ? "active" : ""}`} onClick={() => setTab("secrets")}>
                            🔑 Secrets ({result.secrets.length})
                        </button>
                    </div>

                    {/* Vulnerabilities */}
                    {tab === "vulns" && (
                        <div className="tv-table-wrap">
                            <table className="tv-table">
                                <thead><tr><th style={{ width: 55 }}>Sev</th><th style={{ width: 140 }}>CVE</th><th style={{ width: 160 }}>Package</th><th style={{ width: 90 }}>Installed</th><th style={{ width: 80 }}>Fixed</th><th>Title</th></tr></thead>
                                <tbody>
                                    {result.vulnerabilities.map((v, i) => (
                                        <tr key={i} className="tv-row" style={{ borderLeft: `3px solid ${SEV[v.severity]?.color || "#8c8c8c"}` }}>
                                            <td><span className="tv-sev-badge" style={{ background: SEV[v.severity]?.bg, color: SEV[v.severity]?.color }}>{v.severity.slice(0, 4)}</span></td>
                                            <td>{v.primary_url ? <a href={v.primary_url} target="_blank" rel="noreferrer" className="tv-link">{v.vuln_id}</a> : <code>{v.vuln_id}</code>}</td>
                                            <td><strong>{v.pkg_name}</strong></td>
                                            <td><code className="tv-mono">{v.installed_version}</code></td>
                                            <td>{v.fixed_version && <code className="tv-mono tv-fixed">{v.fixed_version}</code>}</td>
                                            <td style={{ fontSize: 12, color: "#a0a0b0" }}>{v.title}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            {result.vulnerabilities.length === 0 && <div className="tv-empty-tab">✅ No vulnerabilities found</div>}
                        </div>
                    )}

                    {/* Misconfigurations */}
                    {tab === "misconf" && (
                        <div className="tv-results">
                            {result.misconfigurations.map((m, i) => (
                                <div key={i} className="tv-misconf-card">
                                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                        <span className="tv-sev-badge" style={{ background: SEV[m.severity]?.bg, color: SEV[m.severity]?.color }}>{m.severity}</span>
                                        <code className="tv-mono">{m.id}</code>
                                        <strong>{m.title}</strong>
                                    </div>
                                    <div style={{ fontSize: 12, color: "#a0a0b0", marginTop: 4 }}>{m.message}</div>
                                    {m.resolution && <div style={{ fontSize: 11, color: "#52c41a", marginTop: 4 }}>💡 {m.resolution}</div>}
                                </div>
                            ))}
                            {result.misconfigurations.length === 0 && <div className="tv-empty-tab">✅ No misconfigurations found</div>}
                        </div>
                    )}

                    {/* Secrets */}
                    {tab === "secrets" && (
                        <div className="tv-results">
                            {result.secrets.map((sec, i) => (
                                <div key={i} className="tv-misconf-card">
                                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                        <span className="tv-sev-badge" style={{ background: SEV[sec.severity]?.bg, color: SEV[sec.severity]?.color }}>{sec.severity}</span>
                                        <code className="tv-mono">{sec.rule_id}</code>
                                        <strong>{sec.title}</strong>
                                        <span style={{ fontSize: 11, color: "#8c8c8c" }}>({sec.category})</span>
                                    </div>
                                </div>
                            ))}
                            {result.secrets.length === 0 && <div className="tv-empty-tab">✅ No secrets found</div>}
                        </div>
                    )}
                </>
            )}

            {/* Empty state */}
            {!result && !loading && (
                <div className="tv-empty">
                    <div style={{ fontSize: 48, marginBottom: 16 }}>🔍</div>
                    <div style={{ fontSize: 16, marginBottom: 8 }}>Trivy Security Scanner</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 440, lineHeight: 1.6 }}>
                        Scan container images, filesystems, repositories, and IaC configs for vulnerabilities, misconfigurations, and secrets.
                    </div>
                    <div style={{ marginTop: 16, fontSize: 12, color: "#666" }}>
                        Examples: <code>alpine:3.19</code> · <code>/path/to/project</code> · <code>https://github.com/user/repo</code>
                    </div>
                </div>
            )}

            <style>{`
        .tv-form { padding: 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; margin-bottom: 16px; }
        .tv-form-row { display: flex; gap: 12px; }
        .tv-form-group { display: flex; flex-direction: column; gap: 4px; flex: 1; }
        .tv-label { font-size: 10px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .tv-input { padding: 8px 12px; background: #0e0e1a; border: 1px solid #333; border-radius: 8px; color: #e0e0e0; font-size: 14px; font-family: monospace; }
        .tv-input:focus { outline: none; border-color: #722ed1; }
        .tv-select { padding: 8px 12px; background: #0e0e1a; border: 1px solid #333; border-radius: 8px; color: #e0e0e0; font-size: 13px; }
        .tv-btn { padding: 8px 20px; border-radius: 8px; border: 1px solid #333; background: #1a1a2e; color: #e0e0e0; cursor: pointer; font-size: 13px; transition: all 0.2s; }
        .tv-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .tv-btn:disabled { opacity: 0.5; cursor: wait; }
        .tv-btn-primary { border-color: #722ed1; color: #722ed1; }
        .tv-btn-primary:hover { background: #722ed122; }
        .tv-badge { padding: 3px 10px; border-radius: 12px; font-size: 11px; }
        .tv-error { padding: 12px; background: #ff4d4f18; border: 1px solid #ff4d4f44; border-radius: 8px; color: #ff7875; margin-bottom: 16px; font-size: 13px; white-space: pre-wrap; }
        .tv-summary-row { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
        .tv-card { flex: 1; min-width: 80px; padding: 14px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; text-align: center; }
        .tv-card-label { font-size: 10px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .tv-card-val { font-size: 26px; font-weight: 700; margin: 2px 0; }
        .tv-tabs { display: flex; gap: 4px; margin-bottom: 12px; }
        .tv-tab { padding: 8px 16px; border: 1px solid #2a2a4a; border-radius: 8px 8px 0 0; background: transparent; color: #8c8c8c; cursor: pointer; font-size: 12px; transition: all 0.15s; }
        .tv-tab:hover { color: #e0e0e0; }
        .tv-tab.active { background: #16162a; color: #e0e0e0; border-bottom-color: #16162a; }
        .tv-table-wrap { border: 1px solid #2a2a4a; border-radius: 0 12px 12px 12px; overflow: hidden; }
        .tv-table { width: 100%; border-collapse: collapse; }
        .tv-table th { text-align: left; padding: 10px 12px; background: #16162a; color: #8c8c8c; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #2a2a4a; }
        .tv-table td { padding: 8px 12px; border-bottom: 1px solid #1a1a30; font-size: 13px; }
        .tv-row:hover { background: #ffffff06; }
        .tv-sev-badge { padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
        .tv-link { color: #1890ff; text-decoration: none; font-family: monospace; font-size: 12px; }
        .tv-link:hover { text-decoration: underline; }
        .tv-mono { font-family: monospace; font-size: 11px; color: #b8b8cc; background: #ffffff0a; padding: 1px 6px; border-radius: 4px; }
        .tv-fixed { color: #52c41a; }
        .tv-results { display: grid; gap: 8px; }
        .tv-misconf-card { padding: 12px 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 10px; }
        .tv-empty { text-align: center; padding: 80px 20px; color: #666; }
        .tv-empty-tab { text-align: center; padding: 40px; color: #52c41a; font-size: 14px; }
      `}</style>
        </div>
    );
}
