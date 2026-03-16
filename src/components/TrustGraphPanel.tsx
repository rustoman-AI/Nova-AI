import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ExecNodeDef { id: string; kind: string; label: string; description: string; status: string; duration_us: number; output_summary: string; }
interface ExecEdge { from: string; to: string; }
interface PolicyViolation { rule_id: string; component: string; severity: string; message: string; }
interface LicenseAuditItem { component: string; license: string; risk: string; propagates_to: string[]; }
interface TrustEntry { component: string; score: number; }
interface ExecutionGraph { nodes: ExecNodeDef[]; edges: ExecEdge[]; }
interface PipelineResult { graph: ExecutionGraph; violations: PolicyViolation[]; audit_results: LicenseAuditItem[]; trust_scores: TrustEntry[]; report: string[]; total_duration_us: number; verdict: string; }
interface AttackPath { path: string[]; vulnerability_id: string; severity: string; depth: number; risk_score: number; description: string; }
interface RiskSummary { total_nodes: number; total_edges: number; attack_paths: number; critical_paths: number; avg_trust: number; min_trust: number; max_depth: number; exposed_components: number; supply_chain_risk: string; copyleft_risk: number; untrusted_suppliers: number; }
interface TrustGraphData { nodes: { id: string; name: string; node_type: string; trust_score: number; risk_level: string }[]; edges: { from: string; to: string; edge_type: string; weight: number }[]; attack_paths: AttackPath[]; risk_summary: RiskSummary; }

const RISK_C: Record<string, string> = { CRITICAL: "#ff4d4f", HIGH: "#fa8c16", MEDIUM: "#fadb14", LOW: "#52c41a" };
const SEV_C: Record<string, string> = { critical: "#ff4d4f", high: "#fa8c16", medium: "#fadb14", low: "#52c41a", warning: "#fadb14", info: "#1890ff", none: "#666" };
const VERDICT_C: Record<string, string> = { PASS: "#52c41a", FAIL: "#ff4d4f", FAILED: "#ff4d4f" };
const STATUS_C: Record<string, string> = { success: "#52c41a", failed: "#ff4d4f", running: "#1890ff", pending: "#666" };

export default function TrustGraphPanel() {
    const [sbomPath, setSbomPath] = useState("");
    const [pipeline, setPipeline] = useState<PipelineResult | null>(null);
    const [trust, setTrust] = useState<TrustGraphData | null>(null);
    const [loading, setLoading] = useState(false);
    const [tab, setTab] = useState<"pipeline" | "violations" | "trust" | "attacks" | "audit" | "report">("pipeline");

    const runAll = useCallback(async () => {
        if (!sbomPath.trim()) return;
        setLoading(true);
        try {
            const [p, t] = await Promise.all([
                invoke<PipelineResult>("run_devsecops_pipeline", { sbomPath }),
                invoke<TrustGraphData>("build_trust_graph", { sbomPath }),
            ]);
            setPipeline(p);
            setTrust(t);
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [sbomPath]);

    const r = trust?.risk_summary;
    return (
        <div style={{ padding: "24px", maxWidth: 1400, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <h2 style={{ margin: 0 }}>⚡ DevSecOps Pipeline + Trust Graph</h2>
                {pipeline && <span className="tg-badge-lg" style={{ color: VERDICT_C[pipeline.verdict], borderColor: VERDICT_C[pipeline.verdict] }}>{pipeline.verdict}</span>}
            </div>

            <div className="tg-form">
                <div style={{ display: "flex", gap: 8 }}>
                    <input className="tg-input" style={{ flex: 1 }} value={sbomPath} onChange={e => setSbomPath(e.target.value)} placeholder="Path to CycloneDX SBOM JSON" onKeyDown={e => e.key === "Enter" && runAll()} />
                    <button onClick={runAll} disabled={loading || !sbomPath.trim()} className="tg-btn-primary">{loading ? "⏳" : "⚡"} Run Pipeline</button>
                </div>
            </div>

            {pipeline && trust && r && (
                <>
                    {/* Summary cards */}
                    <div className="tg-grid6">
                        <div className="tg-card" style={{ borderTop: `3px solid ${RISK_C[r.supply_chain_risk]}` }}>
                            <div className="tg-lbl">Supply Chain Risk</div>
                            <div className="tg-val" style={{ color: RISK_C[r.supply_chain_risk] }}>{r.supply_chain_risk}</div>
                        </div>
                        <div className="tg-card"><div className="tg-lbl">Graph</div><div className="tg-val">{r.total_nodes}</div><div className="tg-sub">{r.total_edges} edges</div></div>
                        <div className="tg-card"><div className="tg-lbl">Attack Paths</div><div className="tg-val" style={{ color: r.critical_paths > 0 ? "#ff4d4f" : "#52c41a" }}>{r.attack_paths}</div><div className="tg-sub">{r.critical_paths} critical</div></div>
                        <div className="tg-card"><div className="tg-lbl">Avg Trust</div><div className="tg-val">{(r.avg_trust * 100).toFixed(0)}%</div><div className="tg-sub">min {(r.min_trust * 100).toFixed(0)}%</div></div>
                        <div className="tg-card"><div className="tg-lbl">Violations</div><div className="tg-val" style={{ color: pipeline.violations.length > 0 ? "#fa8c16" : "#52c41a" }}>{pipeline.violations.length}</div></div>
                        <div className="tg-card"><div className="tg-lbl">Duration</div><div className="tg-val">{pipeline.total_duration_us < 1000 ? `${pipeline.total_duration_us}μs` : `${(pipeline.total_duration_us / 1000).toFixed(1)}ms`}</div></div>
                    </div>

                    {/* Tabs */}
                    <div className="tg-tabs">{
                        (["pipeline", "violations", "trust", "attacks", "audit", "report"] as const).map(t2 => (
                            <button key={t2} className={`tg-tab ${tab === t2 ? "active" : ""}`} onClick={() => setTab(t2)}>
                                {{ pipeline: "⚡ Pipeline", violations: "⚠️ Violations", trust: "🛡️ Trust", attacks: "💀 Attacks", audit: "📜 Licenses", report: "📊 Report" }[t2]}
                                {t2 === "violations" && ` (${pipeline.violations.length})`}
                                {t2 === "attacks" && ` (${trust.attack_paths.length})`}
                            </button>
                        ))
                    }</div>

                    {/* Pipeline tab */}
                    {tab === "pipeline" && (
                        <div className="tg-pipeline">{pipeline.graph.nodes.map((n, i) => (
                            <div key={n.id} className="tg-step">
                                <div className="tg-step-icon" style={{ color: STATUS_C[n.status] }}>{n.status === "success" ? "✅" : "❌"}</div>
                                <div className="tg-step-body">
                                    <div className="tg-step-title">{n.label}</div>
                                    <div className="tg-step-desc">{n.description}</div>
                                    <div className="tg-step-out">{n.output_summary}</div>
                                </div>
                                <div className="tg-step-time">{n.duration_us < 1000 ? `${n.duration_us}μs` : `${(n.duration_us / 1000).toFixed(1)}ms`}</div>
                                {i < pipeline.graph.nodes.length - 1 && <div className="tg-arrow">↓</div>}
                            </div>
                        ))}</div>
                    )}

                    {/* Violations */}
                    {tab === "violations" && (
                        <div className="tg-table-wrap"><table className="tg-table">
                            <thead><tr><th>Sev</th><th>Rule</th><th>Component</th><th>Message</th></tr></thead>
                            <tbody>{pipeline.violations.map((v, i) => (
                                <tr key={i}><td><span className="tg-sev" style={{ color: SEV_C[v.severity], background: `${SEV_C[v.severity]}18` }}>{v.severity}</span></td><td><code>{v.rule_id}</code></td><td><strong>{v.component}</strong></td><td style={{ fontSize: 12, color: "#a0a0b0" }}>{v.message}</td></tr>
                            ))}</tbody>
                        </table>{pipeline.violations.length === 0 && <div className="tg-empty-t">✅ No violations</div>}</div>
                    )}

                    {/* Trust scores */}
                    {tab === "trust" && (
                        <div className="tg-trust-grid">{pipeline.trust_scores.sort((a, b) => a.score - b.score).slice(0, 50).map((t2, i) => (
                            <div key={i} className="tg-trust-item">
                                <div className="tg-trust-bar"><div style={{ width: `${t2.score * 100}%`, height: "100%", borderRadius: 3, background: t2.score < 0.3 ? "#ff4d4f" : t2.score < 0.7 ? "#fa8c16" : "#52c41a" }} /></div>
                                <span className="tg-trust-pct" style={{ color: t2.score < 0.3 ? "#ff4d4f" : t2.score < 0.7 ? "#fa8c16" : "#52c41a" }}>{(t2.score * 100).toFixed(0)}%</span>
                                <span className="tg-trust-name">{t2.component.split('/').pop()?.split('@')[0] || t2.component}</span>
                            </div>
                        ))}</div>
                    )}

                    {/* Attack paths */}
                    {tab === "attacks" && (
                        <div className="tg-attacks">{trust.attack_paths.slice(0, 20).map((ap, i) => (
                            <div key={i} className="tg-attack-card" style={{ borderLeft: `3px solid ${SEV_C[ap.severity.toLowerCase()] || "#666"}` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                    <span className="tg-sev" style={{ color: SEV_C[ap.severity.toLowerCase()], background: `${SEV_C[ap.severity.toLowerCase()]}18` }}>{ap.severity}</span>
                                    <strong>{ap.vulnerability_id}</strong>
                                    <span style={{ fontSize: 10, color: "#666" }}>depth {ap.depth} · risk {ap.risk_score.toFixed(0)}</span>
                                </div>
                                <div className="tg-attack-path">{ap.path.map((node, j) => (
                                    <span key={j}>{j > 0 && <span className="tg-path-arrow">→</span>}<code className="tg-path-node">{node.split('/').pop()?.split('@')[0] || node}</code></span>
                                ))}</div>
                            </div>
                        ))}{trust.attack_paths.length === 0 && <div className="tg-empty-t">✅ No attack paths</div>}</div>
                    )}

                    {/* License audit */}
                    {tab === "audit" && (
                        <div className="tg-table-wrap"><table className="tg-table">
                            <thead><tr><th>Risk</th><th>Component</th><th>License</th><th>Propagates to</th></tr></thead>
                            <tbody>{pipeline.audit_results.map((a, i) => (
                                <tr key={i}><td><span className="tg-sev" style={{ color: a.risk === "copyleft" ? "#fa8c16" : a.risk === "unknown" ? "#ff4d4f" : "#52c41a", background: a.risk === "copyleft" ? "#fa8c1618" : a.risk === "unknown" ? "#ff4d4f18" : "#52c41a18" }}>{a.risk}</span></td><td>{a.component}</td><td><code>{a.license}</code></td><td style={{ fontSize: 11 }}>{a.propagates_to.join(", ") || "—"}</td></tr>
                            ))}</tbody>
                        </table>{pipeline.audit_results.length === 0 && <div className="tg-empty-t">✅ No audit items</div>}</div>
                    )}

                    {/* Report */}
                    {tab === "report" && (
                        <div className="tg-report">{pipeline.report.map((line, i) => <div key={i} className="tg-report-line">{line}</div>)}</div>
                    )}
                </>
            )}

            {!pipeline && !loading && (
                <div className="tg-empty">
                    <div style={{ fontSize: 48, marginBottom: 12 }}>⚡</div>
                    <div style={{ fontSize: 16, marginBottom: 6 }}>DevSecOps Pipeline + Trust Graph</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 500, lineHeight: 1.6 }}>
                        Transforms a static CycloneDX SBOM into a <strong>computable security graph</strong>:<br />
                        <strong>7-step pipeline</strong> (Load → Index → Trust → Vulns → Licenses → Policy → Report)<br />
                        + <strong>TrustGraph</strong> (attack paths, risk scoring, supply chain analysis)
                    </div>
                </div>
            )}

            <style>{`
        .tg-form{padding:12px;background:#16162a;border:1px solid #2a2a4a;border-radius:12px;margin-bottom:16px}
        .tg-input{padding:8px 12px;background:#0e0e1a;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-family:monospace;font-size:13px}
        .tg-input:focus{outline:none;border-color:#722ed1}
        .tg-btn-primary{padding:8px 20px;border-radius:8px;border:1px solid #722ed1;background:#722ed122;color:#b388ff;cursor:pointer;font-size:13px;font-weight:600;transition:all .2s;white-space:nowrap}
        .tg-btn-primary:hover{background:#722ed144}.tg-btn-primary:disabled{opacity:.5}
        .tg-badge-lg{font-size:14px;font-weight:700;padding:4px 14px;border:2px solid;border-radius:8px}
        .tg-grid6{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:16px}
        .tg-card{padding:12px;background:#16162a;border:1px solid #2a2a4a;border-radius:10px;text-align:center}
        .tg-lbl{font-size:10px;color:#8c8c8c;text-transform:uppercase;letter-spacing:1px}
        .tg-val{font-size:22px;font-weight:700;margin:2px 0}.tg-sub{font-size:10px;color:#666}
        .tg-tabs{display:flex;gap:4px;margin-bottom:12px}
        .tg-tab{padding:8px 14px;border:1px solid #2a2a4a;border-radius:8px 8px 0 0;background:transparent;color:#8c8c8c;cursor:pointer;font-size:12px;transition:all .15s}
        .tg-tab:hover{color:#e0e0e0}.tg-tab.active{background:#16162a;color:#e0e0e0;border-bottom-color:#16162a}
        .tg-pipeline{display:grid;gap:4px}
        .tg-step{display:grid;grid-template-columns:40px 1fr 70px 20px;align-items:center;padding:10px 14px;background:#16162a;border:1px solid #2a2a4a;border-radius:8px}
        .tg-step-icon{font-size:18px;text-align:center}.tg-step-title{font-size:13px;font-weight:600}
        .tg-step-desc{font-size:10px;color:#666}.tg-step-out{font-size:11px;color:#52c41a;margin-top:2px}
        .tg-step-time{font-size:10px;color:#666;text-align:right}.tg-arrow{color:#333;text-align:center}
        .tg-table-wrap{border:1px solid #2a2a4a;border-radius:0 12px 12px 12px;overflow:hidden;max-height:500px;overflow-y:auto}
        .tg-table{width:100%;border-collapse:collapse}
        .tg-table th{text-align:left;padding:8px 10px;background:#16162a;color:#8c8c8c;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #2a2a4a;position:sticky;top:0}
        .tg-table td{padding:6px 10px;border-bottom:1px solid #1a1a30;font-size:12px}
        .tg-table tr:hover{background:#ffffff06}
        .tg-sev{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;text-transform:uppercase}
        .tg-trust-grid{display:grid;gap:4px;max-height:500px;overflow-y:auto}
        .tg-trust-item{display:flex;align-items:center;gap:8px;padding:4px 12px;background:#16162a;border-radius:6px}
        .tg-trust-bar{flex:0 0 120px;height:6px;background:#0e0e1a;border-radius:3px;overflow:hidden}
        .tg-trust-pct{font-size:11px;font-weight:700;width:36px;text-align:right}
        .tg-trust-name{font-size:11px;color:#b8b8cc;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .tg-attacks{display:grid;gap:8px}
        .tg-attack-card{padding:10px 14px;background:#16162a;border:1px solid #2a2a4a;border-radius:8px}
        .tg-attack-path{margin-top:6px;font-size:11px}
        .tg-path-arrow{color:#666;margin:0 4px}
        .tg-path-node{background:#ffffff0a;padding:1px 6px;border-radius:4px;font-size:10px;color:#b388ff}
        .tg-report{padding:16px;background:#16162a;border:1px solid #2a2a4a;border-radius:12px}
        .tg-report-line{padding:4px 0;font-size:13px;color:#b8b8cc;border-bottom:1px solid #1a1a30}
        .tg-empty{text-align:center;padding:60px 20px;color:#666}
        .tg-empty-t{text-align:center;padding:30px;color:#52c41a;font-size:13px}
      `}</style>
        </div>
    );
}
