import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface StageInfo { id: number; name: string; tool: string; status: string; message: string; duration_ms: number; artifacts: string[]; }
interface PipelineReport { stages: StageInfo[]; total_duration_ms: number; sbom_path: string | null; components_count: number; vulns_found: number; profile_verdict: string | null; overall_status: string; }
interface PipelineConfig { project_path: string; output_dir: string; generator: string; schema_version: string; output_format: string; profile_id: string | null; scan_vulns: boolean; enrich: boolean; webhook_url: string | null; }

const STATUS_STYLE: Record<string, { icon: string; color: string; bg: string }> = {
    pending: { icon: "⏳", color: "#8c8c8c", bg: "#8c8c8c12" },
    running: { icon: "🔄", color: "#1890ff", bg: "#1890ff18" },
    success: { icon: "✅", color: "#52c41a", bg: "#52c41a18" },
    warning: { icon: "⚠️", color: "#fa8c16", bg: "#fa8c1618" },
    failed: { icon: "❌", color: "#ff4d4f", bg: "#ff4d4f18" },
    skipped: { icon: "⏭️", color: "#8c8c8c", bg: "#8c8c8c08" },
};

const GENERATORS = [
    { id: "cdxgen", label: "📦 cdxgen", desc: "Auto-detect language" },
    { id: "trivy", label: "🔍 Trivy FS", desc: "Trivy filesystem scan" },
    { id: "gradle-plugin", label: "🐘 Gradle Plugin", desc: "CycloneDX Gradle" },
];

const PROFILES = [
    { id: "dev", label: "Development" }, { id: "staging", label: "Staging" },
    { id: "prod", label: "Production" }, { id: "nist_ssdf", label: "NIST" },
    { id: "ntia", label: "NTIA" }, { id: "cra", label: "EU CRA" },
];

export default function CrossPipelinePanel() {
    const [config, setConfig] = useState<PipelineConfig>({
        project_path: ".", output_dir: "./sbom-pipeline-output", generator: "cdxgen",
        schema_version: "1.6", output_format: "json", profile_id: "prod",
        scan_vulns: true, enrich: true, webhook_url: null,
    });
    const [report, setReport] = useState<PipelineReport | null>(null);
    const [loading, setLoading] = useState(false);

    const runPipeline = useCallback(async () => {
        setLoading(true); setReport(null);
        try {
            const r = await invoke<PipelineReport>("run_cross_pipeline", { config });
            setReport(r);
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [config]);

    const upd = (k: keyof PipelineConfig, v: string | boolean | null) => setConfig(c => ({ ...c, [k]: v }));

    return (
        <div style={{ padding: "24px", maxWidth: 1200, margin: "0 auto" }}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
                <h2 style={{ margin: 0 }}>🔀 Cross-Project SBOM Pipeline</h2>
                <span style={{ fontSize: 11, color: "#8c8c8c", background: "#ffffff08", padding: "3px 10px", borderRadius: 12 }}>7 проектов → единый конвейер</span>
            </div>

            {/* Config form */}
            <div className="cp-form">
                <div className="cp-row">
                    <div className="cp-grp" style={{ flex: 2 }}>
                        <label className="cp-label">Project Path</label>
                        <input className="cp-input" value={config.project_path} onChange={e => upd("project_path", e.target.value)} placeholder="/path/to/project" />
                    </div>
                    <div className="cp-grp" style={{ flex: 2 }}>
                        <label className="cp-label">Output Directory</label>
                        <input className="cp-input" value={config.output_dir} onChange={e => upd("output_dir", e.target.value)} />
                    </div>
                </div>
                <div className="cp-row">
                    <div className="cp-grp">
                        <label className="cp-label">Generator</label>
                        <select className="cp-select" value={config.generator} onChange={e => upd("generator", e.target.value)}>
                            {GENERATORS.map(g => <option key={g.id} value={g.id}>{g.label}</option>)}
                        </select>
                    </div>
                    <div className="cp-grp">
                        <label className="cp-label">Schema Version</label>
                        <select className="cp-select" value={config.schema_version} onChange={e => upd("schema_version", e.target.value)}>
                            {["1.4", "1.5", "1.6"].map(v => <option key={v} value={v}>{v}</option>)}
                        </select>
                    </div>
                    <div className="cp-grp">
                        <label className="cp-label">Validation Profile</label>
                        <select className="cp-select" value={config.profile_id || ""} onChange={e => upd("profile_id", e.target.value || null)}>
                            <option value="">— none —</option>
                            {PROFILES.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
                        </select>
                    </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 16, marginTop: 10 }}>
                    <label className="cp-check"><input type="checkbox" checked={config.scan_vulns} onChange={e => upd("scan_vulns", e.target.checked)} /> 🔍 Scan vulnerabilities</label>
                    <label className="cp-check"><input type="checkbox" checked={config.enrich} onChange={e => upd("enrich", e.target.checked)} /> 🔬 Enrich SBOM</label>
                    <div style={{ flex: 1 }} />
                    <button onClick={runPipeline} disabled={loading} className="cp-btn-run">
                        {loading ? "⏳ Running pipeline..." : "🚀 Run Full Pipeline"}
                    </button>
                </div>
            </div>

            {/* Pipeline visualization */}
            {report && (
                <>
                    {/* Summary bar */}
                    <div className="cp-summary">
                        <div className="cp-sum-item">
                            <span className="cp-sum-label">Status</span>
                            <span style={{ color: report.overall_status === "SUCCESS" ? "#52c41a" : "#ff4d4f", fontWeight: 700 }}>
                                {report.overall_status === "SUCCESS" ? "✅ SUCCESS" : "❌ FAILED"}
                            </span>
                        </div>
                        <div className="cp-sum-item"><span className="cp-sum-label">Components</span><span className="cp-sum-val">{report.components_count}</span></div>
                        <div className="cp-sum-item"><span className="cp-sum-label">Vulns</span><span className="cp-sum-val" style={{ color: report.vulns_found > 0 ? "#fa8c16" : "#52c41a" }}>{report.vulns_found}</span></div>
                        {report.profile_verdict && (
                            <div className="cp-sum-item"><span className="cp-sum-label">Profile</span><span className="cp-sum-val" style={{ color: report.profile_verdict === "PASS" ? "#52c41a" : "#ff4d4f" }}>{report.profile_verdict}</span></div>
                        )}
                        <div className="cp-sum-item"><span className="cp-sum-label">Time</span><span className="cp-sum-val">{(report.total_duration_ms / 1000).toFixed(1)}s</span></div>
                    </div>

                    {/* Stages */}
                    <div className="cp-stages">
                        {report.stages.map((s, i) => {
                            const st = STATUS_STYLE[s.status] || STATUS_STYLE.pending;
                            return (
                                <div key={i} className="cp-stage" style={{ borderLeft: `3px solid ${st.color}` }}>
                                    <div className="cp-stage-head">
                                        <span className="cp-stage-icon">{st.icon}</span>
                                        <span className="cp-stage-name">{s.name}</span>
                                        <span className="cp-stage-tool">{s.tool}</span>
                                        <span className="cp-stage-time">{s.duration_ms}ms</span>
                                        <span className="cp-stage-badge" style={{ background: st.bg, color: st.color }}>{s.status.toUpperCase()}</span>
                                    </div>
                                    <div className="cp-stage-msg">{s.message}</div>
                                    {s.artifacts.length > 0 && (
                                        <div className="cp-stage-arts">{s.artifacts.map((a, j) => <code key={j} className="cp-art">{a.split('/').pop()}</code>)}</div>
                                    )}
                                    {i < report.stages.length - 1 && <div className="cp-arrow">↓</div>}
                                </div>
                            );
                        })}
                    </div>
                </>
            )}

            {/* Empty state */}
            {!report && !loading && (
                <div className="cp-empty">
                    <div style={{ fontSize: 48, marginBottom: 12 }}>🔀</div>
                    <div style={{ fontSize: 16, marginBottom: 6 }}>Cross-Project SBOM Pipeline</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 500, lineHeight: 1.6 }}>
                        Unified pipeline connecting <strong>7 projects</strong>:
                        <br />① Generate (cdxgen / Gradle Plugin / Trivy)
                        <br />② Validate (cyclonedx-cli)
                        <br />③ Transform (cyclonedx-cli convert)
                        <br />④ Scan vulnerabilities (Trivy)
                        <br />⑤ Enrich & Evaluate (Rules + DataStores + Policies)
                        <br />⑥ Export & Notify
                    </div>
                </div>
            )}

            <style>{`
        .cp-form { padding: 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; margin-bottom: 16px; }
        .cp-row { display: flex; gap: 12px; margin-bottom: 10px; }
        .cp-grp { display: flex; flex-direction: column; gap: 4px; flex: 1; }
        .cp-label { font-size: 10px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .cp-input { padding: 8px 12px; background: #0e0e1a; border: 1px solid #333; border-radius: 8px; color: #e0e0e0; font-family: monospace; font-size: 13px; }
        .cp-input:focus { outline: none; border-color: #722ed1; }
        .cp-select { padding: 8px 12px; background: #0e0e1a; border: 1px solid #333; border-radius: 8px; color: #e0e0e0; font-size: 13px; }
        .cp-check { font-size: 12px; color: #a0a0b0; display: flex; align-items: center; gap: 4px; cursor: pointer; }
        .cp-btn-run { padding: 10px 24px; border-radius: 10px; border: 1px solid #722ed1; background: #722ed122; color: #b388ff; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; }
        .cp-btn-run:hover { background: #722ed144; transform: translateY(-1px); box-shadow: 0 4px 16px rgba(114,46,209,0.3); }
        .cp-btn-run:disabled { opacity: 0.5; cursor: wait; }
        .cp-summary { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
        .cp-sum-item { flex: 1; min-width: 80px; padding: 12px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 10px; text-align: center; }
        .cp-sum-label { display: block; font-size: 10px; color: #8c8c8c; text-transform: uppercase; margin-bottom: 4px; }
        .cp-sum-val { font-size: 20px; font-weight: 700; }
        .cp-stages { display: grid; gap: 4px; }
        .cp-stage { padding: 12px 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 10px; position: relative; }
        .cp-stage-head { display: flex; align-items: center; gap: 8px; }
        .cp-stage-icon { font-size: 16px; }
        .cp-stage-name { font-weight: 600; font-size: 13px; }
        .cp-stage-tool { font-size: 11px; color: #8c8c8c; font-family: monospace; }
        .cp-stage-time { font-size: 10px; color: #666; margin-left: auto; }
        .cp-stage-badge { padding: 2px 8px; border-radius: 8px; font-size: 9px; font-weight: 700; letter-spacing: 0.5px; }
        .cp-stage-msg { font-size: 12px; color: #a0a0b0; margin-top: 6px; padding-left: 24px; }
        .cp-stage-arts { display: flex; gap: 6px; margin-top: 6px; padding-left: 24px; flex-wrap: wrap; }
        .cp-art { font-size: 10px; color: #1890ff; background: #1890ff18; padding: 2px 8px; border-radius: 6px; }
        .cp-arrow { text-align: center; color: #333; font-size: 14px; margin: 2px 0; }
        .cp-empty { text-align: center; padding: 60px 20px; color: #666; }
      `}</style>
        </div>
    );
}
