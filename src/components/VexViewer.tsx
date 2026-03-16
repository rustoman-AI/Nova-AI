import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface VulnAnalysis {
    state?: string;
    justification?: string;
    detail?: string;
    response?: string[];
}

interface VulnRating {
    score?: number;
    severity?: string;
    method?: string;
    vector?: string;
    source?: { name?: string; url?: string };
}

interface VulnAffect {
    ref?: string;
    versions?: { version?: string; status?: string }[];
}

interface Vulnerability {
    "bom-ref"?: string;
    id?: string;
    source?: { name?: string; url?: string };
    ratings?: VulnRating[];
    cwes?: number[];
    description?: string;
    detail?: string;
    recommendation?: string;
    advisories?: { title?: string; url?: string }[];
    created?: string;
    published?: string;
    updated?: string;
    analysis?: VulnAnalysis;
    affects?: VulnAffect[];
    properties?: { name?: string; value?: string }[];
}

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
    not_affected: { label: "Not Affected", color: "#22c55e", icon: "✅" },
    affected: { label: "Affected", color: "#ef4444", icon: "🔴" },
    fixed: { label: "Fixed", color: "#3b82f6", icon: "🔵" },
    under_investigation: { label: "Under Investigation", color: "#f59e0b", icon: "🟡" },
};

const SEVERITY_COLORS: Record<string, string> = {
    critical: "#dc2626", high: "#ef4444", medium: "#f59e0b", low: "#22c55e",
    info: "#3b82f6", none: "#94a3b8", unknown: "#64748b",
};

// ─── CVSS Gauge ────────────────────────────────────
function CvssGauge({ score }: { score: number }) {
    const angle = (score / 10) * 180;
    const r = 40;
    const cx = 50, cy = 45;
    const rad = (Math.PI * angle) / 180;
    const x = cx + r * Math.cos(Math.PI - rad);
    const y = cy - r * Math.sin(Math.PI - rad);
    const color = score >= 9 ? "#dc2626" : score >= 7 ? "#ef4444" : score >= 4 ? "#f59e0b" : "#22c55e";

    return (
        <svg viewBox="0 0 100 55" className="vex-gauge">
            <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
                fill="none" stroke="var(--border-subtle)" strokeWidth="6" />
            <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 ${angle > 90 ? 1 : 0} 1 ${x} ${y}`}
                fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" />
            <text x={cx} y={cy - 5} textAnchor="middle" fontSize="14" fontWeight="900" fill={color}>
                {score.toFixed(1)}
            </text>
            <text x={cx} y={cy + 8} textAnchor="middle" fontSize="6" fill="var(--text-muted)">CVSS</text>
        </svg>
    );
}

// ─── Main Component ────────────────────────────────
export default function VexViewer() {
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [selected, setSelected] = useState<Vulnerability | null>(null);
    const [filterStatus, setFilterStatus] = useState<string | null>(null);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM with VEX data",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setVulns(bom.vulnerabilities || []);
        setLoaded(true);
        setSelected(null);
    }, []);

    const stats = useMemo(() => {
        const statusCounts: Record<string, number> = {};
        const sevCounts: Record<string, number> = {};
        let maxCvss = 0;
        for (const v of vulns) {
            const st = v.analysis?.state || "unknown";
            statusCounts[st] = (statusCounts[st] || 0) + 1;
            const sev = v.ratings?.[0]?.severity || "unknown";
            sevCounts[sev] = (sevCounts[sev] || 0) + 1;
            const score = v.ratings?.[0]?.score || 0;
            if (score > maxCvss) maxCvss = score;
        }
        return { statusCounts, sevCounts, maxCvss, total: vulns.length };
    }, [vulns]);

    const filtered = useMemo(() => {
        if (!filterStatus) return vulns;
        return vulns.filter(v => (v.analysis?.state || "unknown") === filterStatus);
    }, [vulns, filterStatus]);

    const hasData = vulns.length > 0;

    return (
        <div className="vex-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">VEX Viewer</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {hasData && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{stats.total} vulnerabilities</span>
                        {Object.entries(stats.statusCounts).map(([st, cnt]) => {
                            const cfg = STATUS_CONFIG[st];
                            return <span key={st} className="depgraph-stat" style={{ color: cfg?.color || "#64748b", borderColor: cfg?.color || "#64748b" }}>
                                {cfg?.icon || "❓"} {cnt} {cfg?.label || st}
                            </span>;
                        })}
                    </div>
                )}
            </div>

            {hasData ? (
                <div className="vex-content fade-in">
                    {/* Status breakdown */}
                    <div className="vex-status-bar">
                        {Object.entries(stats.statusCounts).map(([st, cnt]) => {
                            const cfg = STATUS_CONFIG[st];
                            const pct = (cnt / stats.total) * 100;
                            const isActive = filterStatus === st;
                            return (
                                <div key={st}
                                    className={`vex-status-seg ${isActive ? "vex-status-active" : ""}`}
                                    style={{ width: `${pct}%`, background: cfg?.color || "#64748b" }}
                                    onClick={() => setFilterStatus(filterStatus === st ? null : st)}
                                    title={`${cfg?.label || st}: ${cnt}`}
                                />
                            );
                        })}
                    </div>

                    {/* Severity mini chart + CVSS gauge */}
                    <div className="vex-stats-row">
                        <div className="vex-sev-pills">
                            {Object.entries(stats.sevCounts).sort(([, a], [, b]) => b - a).map(([sev, cnt]) => (
                                <span key={sev} className="vex-sev-pill" style={{
                                    color: SEVERITY_COLORS[sev] || "#64748b",
                                    borderColor: SEVERITY_COLORS[sev] || "#64748b",
                                }}>
                                    {sev}: {cnt}
                                </span>
                            ))}
                        </div>
                        {stats.maxCvss > 0 && (
                            <div className="vex-gauge-wrap">
                                <CvssGauge score={stats.maxCvss} />
                                <div className="vex-gauge-label">Highest CVSS</div>
                            </div>
                        )}
                    </div>

                    {/* List + Detail */}
                    <div className="svc-list-and-detail">
                        <div className="svc-list">
                            {filtered.map((v, i) => {
                                const st = v.analysis?.state || "unknown";
                                const cfg = STATUS_CONFIG[st];
                                const sev = v.ratings?.[0]?.severity || "?";
                                const isActive = selected === v;
                                return (
                                    <div key={i}
                                        className={`svc-node-header ${isActive ? "svc-node-active" : ""}`}
                                        onClick={() => setSelected(v)}
                                    >
                                        <span style={{ color: cfg?.color || "#64748b" }}>{cfg?.icon || "❓"}</span>
                                        <span className="svc-node-name">{v.id || `#${i + 1}`}</span>
                                        <span className="vex-sev-mini" style={{ color: SEVERITY_COLORS[sev] || "#64748b" }}>{sev}</span>
                                        {v.ratings?.[0]?.score !== undefined && (
                                            <span className="svc-mini-badge">{v.ratings[0].score.toFixed(1)}</span>
                                        )}
                                    </div>
                                );
                            })}
                        </div>

                        {selected && (
                            <div className="svc-detail fade-in" style={{ width: 420 }}>
                                <div className="svc-detail-header">
                                    <h3>{selected.id || "?"}</h3>
                                    <button className="merge-file-rm" onClick={() => setSelected(null)}>✕</button>
                                </div>

                                {/* Status + Analysis */}
                                {selected.analysis && (
                                    <div className="vex-analysis">
                                        <span className="vex-status-badge" style={{
                                            color: STATUS_CONFIG[selected.analysis.state || ""]?.color || "#64748b",
                                            borderColor: STATUS_CONFIG[selected.analysis.state || ""]?.color || "#64748b",
                                        }}>
                                            {STATUS_CONFIG[selected.analysis.state || ""]?.icon || "❓"} {STATUS_CONFIG[selected.analysis.state || ""]?.label || selected.analysis.state}
                                        </span>
                                        {selected.analysis.justification && (
                                            <div className="vex-justification">Justification: {selected.analysis.justification.replace(/_/g, " ")}</div>
                                        )}
                                        {selected.analysis.detail && <div className="vex-detail-text">{selected.analysis.detail}</div>}
                                        {selected.analysis.response?.map((r, i) => (
                                            <span key={i} className="vex-response-badge">{r.replace(/_/g, " ")}</span>
                                        ))}
                                    </div>
                                )}

                                {/* Ratings */}
                                {selected.ratings && selected.ratings.length > 0 && (
                                    <div className="ev-section">
                                        <b>📊 Ratings</b>
                                        {selected.ratings.map((r, i) => (
                                            <div key={i} className="vex-rating">
                                                <span className="vex-sev-pill" style={{
                                                    color: SEVERITY_COLORS[r.severity || ""] || "#64748b",
                                                    borderColor: SEVERITY_COLORS[r.severity || ""] || "#64748b",
                                                }}>{r.severity || "?"}</span>
                                                {r.score !== undefined && <span className="svc-mini-badge">{r.score.toFixed(1)}</span>}
                                                {r.method && <span className="prov-mini">{r.method}</span>}
                                                {r.source?.name && <span className="prov-mini">{r.source.name}</span>}
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* Description */}
                                {selected.description && (
                                    <div className="ev-section">
                                        <b>📝 Description</b>
                                        <p className="vex-desc">{selected.description}</p>
                                    </div>
                                )}

                                {/* Recommendation */}
                                {selected.recommendation && (
                                    <div className="ev-section">
                                        <b>💡 Recommendation</b>
                                        <p className="vex-desc">{selected.recommendation}</p>
                                    </div>
                                )}

                                {/* Affects */}
                                {selected.affects && selected.affects.length > 0 && (
                                    <div className="ev-section">
                                        <b>🎯 Affects ({selected.affects.length})</b>
                                        {selected.affects.map((a, i) => (
                                            <div key={i} className="vex-affect">
                                                <code>{a.ref || "?"}</code>
                                                {a.versions?.map((v, j) => (
                                                    <span key={j} className="prov-mini">{v.version} ({v.status})</span>
                                                ))}
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* CWEs */}
                                {selected.cwes && selected.cwes.length > 0 && (
                                    <div className="ev-section">
                                        <b>🏷️ CWEs</b>
                                        <div className="vex-cwes">
                                            {selected.cwes.map((cwe, i) => (
                                                <span key={i} className="vex-cwe">CWE-{cwe}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Timeline */}
                                <div className="ev-section">
                                    <b>📅 Timeline</b>
                                    <div className="vex-timeline">
                                        {selected.created && <div>Created: {selected.created.slice(0, 10)}</div>}
                                        {selected.published && <div>Published: {selected.published.slice(0, 10)}</div>}
                                        {selected.updated && <div>Updated: {selected.updated.slice(0, 10)}</div>}
                                    </div>
                                </div>

                                {/* Advisories */}
                                {selected.advisories && selected.advisories.length > 0 && (
                                    <div className="ev-section">
                                        <b>📎 Advisories</b>
                                        {selected.advisories.map((a, i) => (
                                            <div key={i} className="vex-advisory">{a.title || a.url}</div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🔴</span>
                    <h3>VEX Viewer</h3>
                    <p>Open a CycloneDX BOM with <code>vulnerabilities[]</code> to view VEX status, CVSS scores, affected components, and justifications</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM does not contain vulnerability/VEX data</p>}
                </div>
            )}
        </div>
    );
}
