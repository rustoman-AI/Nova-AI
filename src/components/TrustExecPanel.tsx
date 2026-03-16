import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ExecRuntime { node_id: string; status: string; duration_us: number; output: string; trust_delta: number; }
interface TrustPropagation { component: string; original_trust: number; propagated_trust: number; reason: string; affected_by: string[]; }
interface AttackSurface { entry_point: string; vulnerability: string; severity: string; blast_radius: string[]; depth: number; risk_score: number; }
interface ComplianceReq { id: string; name: string; description: string; status: string; evidence: string; }
interface ComplianceResult { framework: string; requirements: ComplianceReq[]; pass_count: number; fail_count: number; score: number; verdict: string; }
interface TrustExecResult { pipeline: ExecRuntime[]; propagations: TrustPropagation[]; attack_surfaces: AttackSurface[]; compliance: ComplianceResult[]; overall_trust: number; overall_verdict: string; total_duration_us: number; }

const V_C: Record<string, string> = { TRUSTED: "#52c41a", PARTIAL: "#fa8c16", UNTRUSTED: "#ff4d4f", "СООТВЕТСТВУЕТ": "#52c41a", "НЕ СООТВЕТСТВУЕТ": "#ff4d4f", COMPLIANT: "#52c41a", "NON-COMPLIANT": "#ff4d4f", "Level 2+": "#52c41a", "Level 1": "#fa8c16" };
const S_C: Record<string, string> = { pass: "#52c41a", fail: "#ff4d4f", partial: "#fa8c16" };
const SEV_C: Record<string, string> = { critical: "#ff4d4f", CRITICAL: "#ff4d4f", high: "#fa8c16", HIGH: "#fa8c16", medium: "#fadb14", MEDIUM: "#fadb14", low: "#52c41a", LOW: "#52c41a" };
const STEP_ICONS = ["🔧", "📊", "🔗", "💀", "✅"];

export default function TrustExecPanel() {
    const [sbomPath, setSbomPath] = useState("");
    const [result, setResult] = useState<TrustExecResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [tab, setTab] = useState<"pipeline" | "trust" | "attacks" | "compliance">("pipeline");

    const run = useCallback(async () => {
        if (!sbomPath.trim()) return;
        setLoading(true);
        try { setResult(await invoke<TrustExecResult>("run_trust_exec", { sbomPath })); }
        catch (e) { alert(String(e)); }
        setLoading(false);
    }, [sbomPath]);

    const r = result;
    return (
        <div style={{ padding: "24px", maxWidth: 1400, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <h2 style={{ margin: 0 }}>🏛️ Trust Execution Graph</h2>
                {r && <span className="te-verdict" style={{ color: V_C[r.overall_verdict], borderColor: V_C[r.overall_verdict] }}>{r.overall_verdict} ({(r.overall_trust * 100).toFixed(0)}%)</span>}
            </div>

            <div className="te-form">
                <input className="te-inp" style={{ flex: 1 }} value={sbomPath} onChange={e => setSbomPath(e.target.value)} placeholder="Path to CycloneDX SBOM JSON" onKeyDown={e => e.key === "Enter" && run()} />
                <button onClick={run} disabled={loading || !sbomPath.trim()} className="te-btn">{loading ? "⏳" : "🏛️"} Execute</button>
            </div>

            {r && (
                <>
                    {/* Summary */}
                    <div className="te-grid5">
                        <div className="te-card" style={{ borderTop: `3px solid ${V_C[r.overall_verdict]}` }}><div className="te-lbl">Trust</div><div className="te-val" style={{ color: V_C[r.overall_verdict] }}>{(r.overall_trust * 100).toFixed(0)}%</div></div>
                        <div className="te-card"><div className="te-lbl">Propagations</div><div className="te-val">{r.propagations.length}</div></div>
                        <div className="te-card"><div className="te-lbl">Attack Surfaces</div><div className="te-val" style={{ color: r.attack_surfaces.length > 0 ? "#ff4d4f" : "#52c41a" }}>{r.attack_surfaces.length}</div></div>
                        <div className="te-card"><div className="te-lbl">Compliance</div><div className="te-val">{r.compliance.filter(c => c.fail_count === 0).length}/{r.compliance.length}</div></div>
                        <div className="te-card"><div className="te-lbl">Duration</div><div className="te-val">{r.total_duration_us < 1000 ? `${r.total_duration_us}μs` : `${(r.total_duration_us / 1000).toFixed(1)}ms`}</div></div>
                    </div>

                    {/* Tabs */}
                    <div className="te-tabs">{(["pipeline", "trust", "attacks", "compliance"] as const).map(t => (
                        <button key={t} className={`te-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
                            {{ pipeline: "⚡ Pipeline", trust: "🔗 Propagation", attacks: "💀 Surface", compliance: "🏛️ Compliance" }[t]}
                        </button>
                    ))}</div>

                    {/* Pipeline */}
                    {tab === "pipeline" && <div className="te-steps">{r.pipeline.map((s, i) => (
                        <div key={s.node_id} className="te-step">
                            <span className="te-step-icon">{STEP_ICONS[i] || "⚙️"}</span>
                            <div className="te-step-body">
                                <div className="te-step-name">{s.node_id.replace(/_/g, " ")}</div>
                                <div className="te-step-out">{s.output}</div>
                            </div>
                            {s.trust_delta !== 0 && <span style={{ fontSize: 11, color: s.trust_delta < 0 ? "#ff4d4f" : "#52c41a" }}>{s.trust_delta > 0 ? "+" : ""}{(s.trust_delta * 100).toFixed(1)}%</span>}
                            <span className="te-step-time">{s.duration_us}μs</span>
                        </div>
                    ))}</div>}

                    {/* Trust propagation */}
                    {tab === "trust" && (
                        <div className="te-tbl-wrap"><table className="te-tbl">
                            <thead><tr><th>Component</th><th>Original</th><th>Propagated</th><th>Δ</th><th>Reason</th></tr></thead>
                            <tbody>{r.propagations.map((p, i) => {
                                const delta = p.propagated_trust - p.original_trust;
                                return (
                                    <tr key={i}>
                                        <td><strong>{p.component}</strong></td>
                                        <td style={{ color: "#666" }}>{(p.original_trust * 100).toFixed(0)}%</td>
                                        <td style={{ color: p.propagated_trust < 0.3 ? "#ff4d4f" : p.propagated_trust < 0.7 ? "#fa8c16" : "#52c41a" }}>{(p.propagated_trust * 100).toFixed(0)}%</td>
                                        <td style={{ color: "#ff4d4f" }}>{(delta * 100).toFixed(1)}%</td>
                                        <td style={{ fontSize: 11, color: "#888" }}>{p.reason}</td>
                                    </tr>);
                            })}</tbody>
                        </table>{r.propagations.length === 0 && <div className="te-empty">✅ No trust degradation</div>}</div>
                    )}

                    {/* Attack surfaces */}
                    {tab === "attacks" && <div className="te-attacks">{r.attack_surfaces.map((a, i) => (
                        <div key={i} className="te-attack" style={{ borderLeft: `3px solid ${SEV_C[a.severity] || "#666"}` }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span className="te-sev" style={{ color: SEV_C[a.severity], background: `${SEV_C[a.severity] || "#666"}18` }}>{a.severity}</span>
                                <strong>{a.vulnerability}</strong>
                                <span style={{ fontSize: 10, color: "#666" }}>blast: {a.blast_radius.length} · risk: {a.risk_score.toFixed(0)}</span>
                            </div>
                            <div className="te-blast">{a.blast_radius.slice(0, 8).map((c, j) => (
                                <code key={j} className="te-blast-node">{c.split('/').pop()?.split('@')[0] || c}</code>
                            ))}{a.blast_radius.length > 8 && <span style={{ color: "#666", fontSize: 10 }}>+{a.blast_radius.length - 8}</span>}</div>
                        </div>
                    ))}{r.attack_surfaces.length === 0 && <div className="te-empty">✅ No attack surfaces</div>}</div>}

                    {/* Compliance */}
                    {tab === "compliance" && <div className="te-compliance">{r.compliance.map((c, i) => (
                        <div key={i} className="te-fw">
                            <div className="te-fw-header">
                                <span className="te-fw-name">{c.framework}</span>
                                <span className="te-fw-score" style={{ color: V_C[c.verdict] || "#666" }}>{c.score.toFixed(0)}%</span>
                                <span className="te-fw-verdict" style={{ color: V_C[c.verdict], background: `${V_C[c.verdict] || "#666"}18` }}>{c.verdict}</span>
                            </div>
                            <table className="te-tbl te-fw-tbl">
                                <tbody>{c.requirements.map(rq => (
                                    <tr key={rq.id}>
                                        <td style={{ width: 70 }}><code>{rq.id}</code></td>
                                        <td style={{ width: 30 }}><span style={{ color: S_C[rq.status] }}>{rq.status === "pass" ? "✅" : rq.status === "fail" ? "❌" : "⚠️"}</span></td>
                                        <td>{rq.name}</td>
                                        <td style={{ fontSize: 11, color: "#666" }}>{rq.evidence}</td>
                                    </tr>
                                ))}</tbody>
                            </table>
                        </div>
                    ))}</div>}
                </>
            )}

            {!r && !loading && (
                <div className="te-empty-state">
                    <div style={{ fontSize: 48 }}>🏛️</div>
                    <div style={{ fontSize: 16, margin: "8px 0" }}>Trust Execution Graph</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 520, lineHeight: 1.6 }}>
                        <strong>Formal DevSecOps pipeline</strong> that transforms static SBOM into a computable trust model:<br />
                        ① Build indices → ② Base trust → ③ Trust propagation → ④ Attack surface → ⑤ Multi-framework compliance<br /><br />
                        Frameworks: <strong>CycloneDX</strong> · <strong>NTIA</strong> · <strong>NIST</strong> · <strong>EU CRA</strong> · <strong>SLSA</strong>
                    </div>
                </div>
            )}

            <style>{`
        .te-form{display:flex;gap:8px;padding:12px;background:#16162a;border:1px solid #2a2a4a;border-radius:12px;margin-bottom:16px}
        .te-inp{padding:8px 12px;background:#0e0e1a;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-family:monospace;font-size:13px}
        .te-inp:focus{outline:none;border-color:#722ed1}
        .te-btn{padding:8px 20px;border-radius:8px;border:1px solid #722ed1;background:#722ed122;color:#b388ff;cursor:pointer;font-size:13px;font-weight:600;white-space:nowrap}
        .te-btn:disabled{opacity:.5}.te-btn:hover{background:#722ed144}
        .te-verdict{font-size:14px;font-weight:700;padding:4px 14px;border:2px solid;border-radius:8px}
        .te-grid5{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:16px}
        .te-card{padding:12px;background:#16162a;border:1px solid #2a2a4a;border-radius:10px;text-align:center}
        .te-lbl{font-size:10px;color:#8c8c8c;text-transform:uppercase;letter-spacing:1px}
        .te-val{font-size:22px;font-weight:700;margin:2px 0}
        .te-tabs{display:flex;gap:4px;margin-bottom:12px}
        .te-tab{padding:8px 14px;border:1px solid #2a2a4a;border-radius:8px 8px 0 0;background:transparent;color:#8c8c8c;cursor:pointer;font-size:12px;transition:all .15s}
        .te-tab:hover{color:#e0e0e0}.te-tab.active{background:#16162a;color:#e0e0e0;border-bottom-color:#16162a}
        .te-steps{display:grid;gap:4px}
        .te-step{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#16162a;border:1px solid #2a2a4a;border-radius:8px}
        .te-step-icon{font-size:18px}.te-step-body{flex:1}
        .te-step-name{font-size:12px;font-weight:600;text-transform:capitalize}
        .te-step-out{font-size:11px;color:#52c41a}.te-step-time{font-size:10px;color:#666}
        .te-tbl-wrap{border:1px solid #2a2a4a;border-radius:0 12px 12px 12px;overflow:auto;max-height:500px}
        .te-tbl{width:100%;border-collapse:collapse}
        .te-tbl th{text-align:left;padding:6px 10px;background:#16162a;color:#8c8c8c;font-size:10px;text-transform:uppercase;border-bottom:1px solid #2a2a4a;position:sticky;top:0}
        .te-tbl td{padding:5px 10px;border-bottom:1px solid #1a1a30;font-size:12px}
        .te-tbl tr:hover{background:#ffffff06}
        .te-attacks{display:grid;gap:8px}
        .te-attack{padding:10px 14px;background:#16162a;border:1px solid #2a2a4a;border-radius:8px}
        .te-sev{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;text-transform:uppercase}
        .te-blast{margin-top:6px;display:flex;flex-wrap:wrap;gap:4px}
        .te-blast-node{font-size:10px;color:#b388ff;background:#722ed118;padding:2px 6px;border-radius:4px}
        .te-compliance{display:grid;gap:12px}
        .te-fw{border:1px solid #2a2a4a;border-radius:10px;overflow:hidden}
        .te-fw-header{padding:10px 14px;background:#0e0e1a;display:flex;align-items:center;gap:10px;border-bottom:1px solid #2a2a4a}
        .te-fw-name{font-weight:600;font-size:13px;flex:1}
        .te-fw-score{font-size:16px;font-weight:700}
        .te-fw-verdict{padding:2px 10px;border-radius:8px;font-size:11px;font-weight:600}
        .te-fw-tbl td{padding:4px 10px}
        .te-empty{text-align:center;padding:30px;color:#52c41a;font-size:13px}
        .te-empty-state{text-align:center;padding:60px 20px;color:#666}
      `}</style>
        </div>
    );
}
