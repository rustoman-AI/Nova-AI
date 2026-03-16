import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";

interface SbomStats { total_components: number; total_dependencies: number; total_vulnerabilities: number; with_license: number; with_supplier: number; with_purl: number; with_hash: number; with_version: number; license_coverage: number; supplier_coverage: number; purl_coverage: number; hash_coverage: number; avg_trust_score: number; critical_vulns: number; high_vulns: number; }
interface GraphSummary { total_nodes: number; exec_nodes: number; sbom_components: number; rule_nodes: number; artifact_nodes: number; total_edges: number; sbom_stats: SbomStats | null; trust_verdict: string; compliance_score: number; }
interface QueryResult { query: string; total: number; items: Record<string, unknown>[]; duration_us: number; }

const QUERY_PRESETS = [
    { label: "All Components", target: "components", filters: [], sort: "name" },
    { label: "🔓 Unlicensed", target: "unlicensed", filters: [], sort: null },
    { label: "👤 No Supplier", target: "no_supplier", filters: [], sort: null },
    { label: "🔴 Critical Vulns", target: "critical", filters: [], sort: null },
    { label: "📜 Copyleft Propagation", target: "copyleft", filters: [], sort: null },
    { label: "⚠️ Vulnerabilities", target: "vulnerabilities", filters: [], sort: null },
    { label: "🏆 Top Trust Score", target: "components", filters: [], sort: "trust_score" },
    { label: "🐛 Most Vulnerable", target: "components", filters: [], sort: "vuln_count" },
];

const TRUST_COLORS: Record<string, string> = { TRUSTED: "#52c41a", PARTIAL: "#fa8c16", UNTRUSTED: "#ff4d4f" };

export default function UnifiedGraphPanel() {
    const [sbomPath, setSbomPath] = useState("");
    const [summary, setSummary] = useState<GraphSummary | null>(null);
    const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [customTarget, setCustomTarget] = useState("components");
    const [customField, setCustomField] = useState("name");
    const [customOp, setCustomOp] = useState("contains");
    const [customValue, setCustomValue] = useState("");

    const loadGraph = useCallback(async () => {
        if (!sbomPath.trim()) return;
        setLoading(true);
        try {
            const s = await invoke<GraphSummary>("build_system_graph", { sbomPath });
            setSummary(s);
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [sbomPath]);

    const runQuery = useCallback(async (target: string, filters: { field: string; op: string; value: string }[], sort: string | null) => {
        if (!sbomPath.trim()) return;
        try {
            const r = await invoke<QueryResult>("query_sbom_graph", {
                sbomPath, query: { target, filters, sort_by: sort, limit: 50 },
            });
            setQueryResult(r);
        } catch (e) { alert(String(e)); }
    }, [sbomPath]);

    const runCustomQuery = useCallback(() => {
        const filters = customValue ? [{ field: customField, op: customOp, value: customValue }] : [];
        runQuery(customTarget, filters, null);
    }, [customTarget, customField, customOp, customValue, runQuery]);

    const st = summary?.sbom_stats;

    return (
        <div style={{ padding: "24px", maxWidth: 1400, margin: "0 auto" }}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <h2 style={{ margin: 0 }}>🔮 Unified Graph Model</h2>
                <span className="ug-badge">ExecutionGraph + SBOMGraph + RuleGraph + ArtifactGraph</span>
            </div>

            {/* SBOM Input */}
            <div className="ug-form">
                <div style={{ display: "flex", gap: 8 }}>
                    <input className="ug-input" style={{ flex: 1 }} value={sbomPath} onChange={e => setSbomPath(e.target.value)} placeholder="Path to CycloneDX SBOM JSON (bom.json)" />
                    <button onClick={loadGraph} disabled={loading || !sbomPath.trim()} className="ug-btn-primary">{loading ? "⏳" : "🔮"} Build Graph</button>
                </div>
            </div>

            {/* Graph Summary */}
            {summary && (
                <>
                    <div className="ug-grid4">
                        <div className="ug-card" style={{ borderTop: `3px solid ${TRUST_COLORS[summary.trust_verdict] || "#666"}` }}>
                            <div className="ug-card-label">Trust Verdict</div>
                            <div className="ug-card-val" style={{ color: TRUST_COLORS[summary.trust_verdict] }}>{summary.trust_verdict}</div>
                            <div className="ug-card-sub">{(summary.compliance_score).toFixed(1)}% compliance</div>
                        </div>
                        <div className="ug-card"><div className="ug-card-label">Total Nodes</div><div className="ug-card-val">{summary.total_nodes}</div>
                            <div className="ug-card-sub">{summary.exec_nodes} exec · {summary.sbom_components} SBOM · {summary.rule_nodes} rules · {summary.artifact_nodes} artifacts</div></div>
                        <div className="ug-card"><div className="ug-card-label">Edges</div><div className="ug-card-val">{summary.total_edges}</div>
                            <div className="ug-card-sub">cross-graph links</div></div>
                        <div className="ug-card"><div className="ug-card-label">Vulns</div>
                            <div className="ug-card-val" style={{ color: (st?.critical_vulns || 0) > 0 ? "#ff4d4f" : "#52c41a" }}>{st?.total_vulnerabilities || 0}</div>
                            <div className="ug-card-sub">{st?.critical_vulns || 0} critical · {st?.high_vulns || 0} high</div></div>
                    </div>

                    {/* Coverage bars */}
                    {st && (
                        <div className="ug-coverage">
                            <CoverageBar label="License" value={st.license_coverage} color="#1890ff" count={st.with_license} total={st.total_components} />
                            <CoverageBar label="Supplier" value={st.supplier_coverage} color="#52c41a" count={st.with_supplier} total={st.total_components} />
                            <CoverageBar label="PURL" value={st.purl_coverage} color="#722ed1" count={st.with_purl} total={st.total_components} />
                            <CoverageBar label="Hash" value={st.hash_coverage} color="#fa8c16" count={st.with_hash} total={st.total_components} />
                            <CoverageBar label="Trust" value={st.avg_trust_score * 100} color={TRUST_COLORS[summary.trust_verdict] || "#666"} count={Math.round(st.avg_trust_score * st.total_components)} total={st.total_components} />
                        </div>
                    )}

                    {/* Query Engine */}
                    <div className="ug-query-section">
                        <div className="ug-query-header">
                            <span style={{ fontSize: 14, fontWeight: 600 }}>🔍 SBOM Query Engine</span>
                        </div>

                        {/* Presets */}
                        <div className="ug-presets">
                            {QUERY_PRESETS.map((p, i) => (
                                <button key={i} className="ug-preset-btn" onClick={() => runQuery(p.target, p.filters, p.sort)}>
                                    {p.label}
                                </button>
                            ))}
                        </div>

                        {/* Custom query builder */}
                        <div className="ug-custom-query">
                            <select className="ug-sel" value={customTarget} onChange={e => setCustomTarget(e.target.value)}>
                                <option value="components">components</option>
                                <option value="vulnerabilities">vulnerabilities</option>
                                <option value="unlicensed">unlicensed</option>
                                <option value="no_supplier">no_supplier</option>
                                <option value="copyleft">copyleft</option>
                                <option value="critical">critical</option>
                            </select>
                            <span style={{ color: "#666" }}>where</span>
                            <select className="ug-sel" value={customField} onChange={e => setCustomField(e.target.value)}>
                                {["name", "version", "type", "group", "purl", "license", "supplier", "scope", "severity", "id", "source"].map(f => <option key={f} value={f}>{f}</option>)}
                            </select>
                            <select className="ug-sel" value={customOp} onChange={e => setCustomOp(e.target.value)}>
                                {["eq", "ne", "contains", "exists", "not_exists"].map(o => <option key={o} value={o}>{o}</option>)}
                            </select>
                            <input className="ug-input-sm" value={customValue} onChange={e => setCustomValue(e.target.value)} placeholder="value" onKeyDown={e => e.key === "Enter" && runCustomQuery()} />
                            <button onClick={runCustomQuery} className="ug-btn-sm">▶ Run</button>
                        </div>

                        {/* Results */}
                        {queryResult && (
                            <div className="ug-results">
                                <div className="ug-results-header">
                                    <span>{queryResult.total} results</span>
                                    <span style={{ color: "#666" }}>{queryResult.duration_us}μs</span>
                                    <span style={{ color: "#666", fontSize: 11 }}>{queryResult.query}</span>
                                </div>
                                <div className="ug-results-table">
                                    {queryResult.items.length > 0 && (
                                        <table className="ug-table">
                                            <thead><tr>{Object.keys(queryResult.items[0]).map(k => <th key={k}>{k}</th>)}</tr></thead>
                                            <tbody>
                                                {queryResult.items.map((item, i) => (
                                                    <tr key={i}>{Object.values(item).map((v, j) => {
                                                        const txt = typeof v === "object" ? JSON.stringify(v) : String(v ?? "");
                                                        return (
                                                            <td key={j} onClick={() => emit('open-knowledge-panel', { query: txt })} className="ug-clickable-cell">
                                                                {txt}
                                                            </td>
                                                        );
                                                    })}</tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    )}
                                    {queryResult.items.length === 0 && <div className="ug-empty-q">No results</div>}
                                </div>
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* Empty state */}
            {!summary && !loading && (
                <div className="ug-empty">
                    <div style={{ fontSize: 48, marginBottom: 12 }}>🔮</div>
                    <div style={{ fontSize: 16, marginBottom: 6 }}>Unified Graph Model</div>
                    <div style={{ color: "#8c8c8c", maxWidth: 500, lineHeight: 1.6 }}>
                        Load a CycloneDX SBOM to build a <strong>multi-graph</strong> connecting:<br />
                        ExecutionGraph (pipeline) + SBOMGraph (components) + RuleGraph (policies) + ArtifactGraph (outputs)<br /><br />
                        Then use the <strong>SBOM Query Engine</strong> to query graph entities.
                    </div>
                </div>
            )}

            <style>{`
        .ug-badge { font-size: 10px; color: #722ed1; background: #722ed118; padding: 3px 10px; border-radius: 12px; }
        .ug-form { padding: 12px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; margin-bottom: 16px; }
        .ug-input { padding: 8px 12px; background: #0e0e1a; border: 1px solid #333; border-radius: 8px; color: #e0e0e0; font-family: monospace; font-size: 13px; }
        .ug-input:focus { outline: none; border-color: #722ed1; }
        .ug-btn-primary { padding: 8px 20px; border-radius: 8px; border: 1px solid #722ed1; background: #722ed122; color: #b388ff; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; white-space: nowrap; }
        .ug-btn-primary:hover { background: #722ed144; }
        .ug-btn-primary:disabled { opacity: 0.5; }
        .ug-grid4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 16px; }
        .ug-card { padding: 14px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; text-align: center; }
        .ug-card-label { font-size: 10px; color: #8c8c8c; text-transform: uppercase; letter-spacing: 1px; }
        .ug-card-val { font-size: 24px; font-weight: 700; margin: 4px 0; }
        .ug-card-sub { font-size: 10px; color: #666; }
        .ug-coverage { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 16px; }
        .ug-cov-item { padding: 10px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 10px; }
        .ug-cov-label { font-size: 10px; color: #8c8c8c; display: flex; justify-content: space-between; margin-bottom: 4px; }
        .ug-cov-bar { height: 6px; background: #0e0e1a; border-radius: 3px; overflow: hidden; }
        .ug-cov-fill { height: 100%; border-radius: 3px; transition: width 0.5s; }
        .ug-query-section { padding: 16px; background: #16162a; border: 1px solid #2a2a4a; border-radius: 12px; }
        .ug-query-header { margin-bottom: 12px; }
        .ug-presets { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
        .ug-preset-btn { padding: 6px 12px; border: 1px solid #2a2a4a; border-radius: 8px; background: transparent; color: #8c8c8c; cursor: pointer; font-size: 11px; transition: all 0.15s; }
        .ug-preset-btn:hover { color: #b388ff; border-color: #722ed1; background: #722ed111; }
        .ug-custom-query { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; padding: 8px 12px; background: #0e0e1a; border-radius: 8px; }
        .ug-sel { padding: 4px 8px; background: #16162a; border: 1px solid #333; border-radius: 6px; color: #e0e0e0; font-size: 12px; font-family: monospace; }
        .ug-input-sm { padding: 4px 8px; background: #16162a; border: 1px solid #333; border-radius: 6px; color: #e0e0e0; font-size: 12px; font-family: monospace; width: 120px; }
        .ug-btn-sm { padding: 4px 12px; border: 1px solid #722ed1; border-radius: 6px; background: #722ed122; color: #b388ff; cursor: pointer; font-size: 12px; }
        .ug-results { border: 1px solid #2a2a4a; border-radius: 8px; overflow: hidden; }
        .ug-results-header { padding: 8px 12px; background: #0e0e1a; font-size: 12px; display: flex; gap: 12px; align-items: center; border-bottom: 1px solid #2a2a4a; }
        .ug-results-table { overflow-x: auto; max-height: 400px; overflow-y: auto; }
        .ug-table { width: 100%; border-collapse: collapse; }
        .ug-table th { text-align: left; padding: 6px 10px; background: #16162a; color: #8c8c8c; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #2a2a4a; position: sticky; top: 0; }
        .ug-table td { padding: 5px 10px; border-bottom: 1px solid #1a1a30; font-size: 12px; color: #b8b8cc; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .ug-clickable-cell:hover { cursor: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23722ed1" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>') 8 8, auto; color: #b388ff; background: #722ed111; text-decoration: underline; }
        .ug-table tr:hover { background: #ffffff06; }
        .ug-empty { text-align: center; padding: 60px 20px; color: #666; }
        .ug-empty-q { text-align: center; padding: 20px; color: #666; font-size: 12px; }
      `}</style>
        </div>
    );
}

function CoverageBar({ label, value, color, count, total }: { label: string; value: number; color: string; count: number; total: number }) {
    return (
        <div className="ug-cov-item">
            <div className="ug-cov-label"><span>{label}</span><span style={{ color }}>{value.toFixed(0)}% ({count}/{total})</span></div>
            <div className="ug-cov-bar"><div className="ug-cov-fill" style={{ width: `${Math.min(value, 100)}%`, background: color }} /></div>
        </div>
    );
}
