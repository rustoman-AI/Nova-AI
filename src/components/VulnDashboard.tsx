import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import DropZone from "./DropZone";

interface Vulnerability {
    id: string;
    source?: { name?: string; url?: string };
    ratings?: { severity?: string; score?: number; method?: string }[];
    description?: string;
    affects?: { ref: string }[];
    cwes?: number[];
    recommendation?: string;
}

interface VulnSummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    unknown: number;
    topAffected: { ref: string; count: number }[];
    scoreDistribution: { range: string; count: number }[];
}

function getSeverity(v: Vulnerability): string {
    if (!v.ratings || v.ratings.length === 0) return "unknown";
    return v.ratings[0].severity?.toLowerCase() || "unknown";
}

function getScore(v: Vulnerability): number | null {
    if (!v.ratings || v.ratings.length === 0) return null;
    return v.ratings[0].score ?? null;
}

function buildSummary(vulns: Vulnerability[]): VulnSummary {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
    const affectedMap = new Map<string, number>();
    const scoreBuckets = [
        { range: "9.0-10", count: 0 }, { range: "7.0-8.9", count: 0 },
        { range: "4.0-6.9", count: 0 }, { range: "0.1-3.9", count: 0 },
        { range: "0 / N/A", count: 0 },
    ];

    for (const v of vulns) {
        const sev = getSeverity(v);
        if (sev in counts) counts[sev as keyof typeof counts]++;
        else counts.unknown++;

        const score = getScore(v);
        if (score === null || score === 0) scoreBuckets[4].count++;
        else if (score >= 9) scoreBuckets[0].count++;
        else if (score >= 7) scoreBuckets[1].count++;
        else if (score >= 4) scoreBuckets[2].count++;
        else scoreBuckets[3].count++;

        for (const a of (v.affects || [])) {
            affectedMap.set(a.ref, (affectedMap.get(a.ref) || 0) + 1);
        }
    }

    const topAffected = Array.from(affectedMap.entries())
        .map(([ref, count]) => ({ ref, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

    return {
        total: vulns.length,
        ...counts,
        topAffected,
        scoreDistribution: scoreBuckets,
    };
}

// SVG Donut chart
function DonutChart({ data }: { data: { label: string; value: number; color: string }[] }) {
    const total = data.reduce((s, d) => s + d.value, 0);
    if (total === 0) return <div className="donut-empty">No vulnerabilities</div>;

    const size = 160;
    const stroke = 28;
    const radius = (size - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;

    return (
        <div className="donut-container">
            <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
                {data.filter(d => d.value > 0).map((d) => {
                    const pct = d.value / total;
                    const dashArray = `${circumference * pct} ${circumference * (1 - pct)}`;
                    const dashOffset = -offset * circumference;
                    offset += pct;
                    return (
                        <circle
                            key={d.label}
                            cx={size / 2} cy={size / 2} r={radius}
                            fill="none" stroke={d.color} strokeWidth={stroke}
                            strokeDasharray={dashArray} strokeDashoffset={dashOffset}
                            transform={`rotate(-90 ${size / 2} ${size / 2})`}
                            className="donut-segment"
                        />
                    );
                })}
                <text x={size / 2} y={size / 2 - 6} textAnchor="middle" className="donut-total">{total}</text>
                <text x={size / 2} y={size / 2 + 14} textAnchor="middle" className="donut-label">total</text>
            </svg>
            <div className="donut-legend">
                {data.filter(d => d.value > 0).map((d) => (
                    <div key={d.label} className="legend-item">
                        <span className="legend-dot" style={{ background: d.color }} />
                        <span className="legend-label">{d.label}</span>
                        <span className="legend-value">{d.value}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}

// CVSS Score bar chart
function ScoreChart({ data }: { data: { range: string; count: number }[] }) {
    const max = Math.max(...data.map(d => d.count), 1);
    const colors = ["#ef4444", "#f97316", "#f59e0b", "#22c55e", "#64748b"];
    return (
        <div className="score-chart">
            {data.map((d, i) => (
                <div key={d.range} className="score-bar-row">
                    <span className="score-bar-label">{d.range}</span>
                    <div className="score-bar-track">
                        <div
                            className="score-bar-fill"
                            style={{ width: `${(d.count / max) * 100}%`, background: colors[i] }}
                        />
                    </div>
                    <span className="score-bar-value">{d.count}</span>
                </div>
            ))}
        </div>
    );
}

export default function VulnDashboard() {
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const [summary, setSummary] = useState<VulnSummary | null>(null);
    const [filePath, setFilePath] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [expandedVuln, setExpandedVuln] = useState<string | null>(null);

    const severityColors = useMemo(() => ({
        critical: "#ef4444", high: "#f97316", medium: "#f59e0b",
        low: "#22c55e", info: "#3b82f6", unknown: "#64748b",
    }), []);

    const donutData = useMemo(() => {
        if (!summary) return [];
        return [
            { label: "Critical", value: summary.critical, color: severityColors.critical },
            { label: "High", value: summary.high, color: severityColors.high },
            { label: "Medium", value: summary.medium, color: severityColors.medium },
            { label: "Low", value: summary.low, color: severityColors.low },
            { label: "Info", value: summary.info, color: severityColors.info },
            { label: "Unknown", value: summary.unknown, color: severityColors.unknown },
        ];
    }, [summary, severityColors]);

    const loadBom = useCallback(async (path: string) => {
        setLoading(true);
        setError(null);
        try {
            const content = await invoke<string>("read_file_contents", { path });
            const bom = JSON.parse(content);
            const v: Vulnerability[] = bom.vulnerabilities || [];
            setVulns(v);
            setSummary(buildSummary(v));
            setFilePath(path);
        } catch (err: any) {
            setError(err?.toString?.() ?? String(err));
        }
        setLoading(false);
    }, []);

    const openFile = useCallback(async () => {
        const file = await open({
            multiple: false,
            filters: [{ name: "JSON BOM", extensions: ["json"] }],
        });
        if (file) loadBom(file as string);
    }, [loadBom]);

    if (!summary) {
        return (
            <DropZone onFileDrop={loadBom} className="vuln-drop-full">
                <div className="vuln-empty">
                    <span className="vuln-empty-icon">🛡️</span>
                    <h3>Vulnerability Dashboard</h3>
                    <p>Open a CycloneDX BOM with vulnerabilities to analyze</p>
                    <button className="exec-btn" onClick={openFile} disabled={loading}>
                        {loading ? <><span className="spinner" /> Loading…</> : <>📂 Open BOM</>}
                    </button>
                    {error && <div className="json-error">{error}</div>}
                </div>
            </DropZone>
        );
    }

    return (
        <div className="vuln-dashboard">
            {/* Top bar */}
            <div className="vuln-top-bar">
                <span className="json-file-path" title={filePath || ""}>🛡️ {filePath?.split("/").pop()}</span>
                <span className="vuln-total-badge">{summary.total} vulnerabilities</span>
                <button className="preset-btn" onClick={openFile}>Open Another</button>
                <button className="preset-btn" onClick={() => { setSummary(null); setVulns([]); }}>Close</button>
            </div>

            {/* Severity cards */}
            <div className="vuln-severity-cards">
                {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                    <div key={sev} className={`vuln-sev-card vuln-sev-${sev}`}>
                        <span className="vuln-sev-value">{summary[sev]}</span>
                        <span className="vuln-sev-label">{sev}</span>
                    </div>
                ))}
            </div>

            {/* Charts row */}
            <div className="vuln-charts-row">
                <div className="vuln-chart-card">
                    <h4>Severity Distribution</h4>
                    <DonutChart data={donutData} />
                </div>
                <div className="vuln-chart-card">
                    <h4>CVSS Score Distribution</h4>
                    <ScoreChart data={summary.scoreDistribution} />
                </div>
            </div>

            {/* Top affected */}
            {summary.topAffected.length > 0 && (
                <div className="vuln-affected">
                    <h4>Top Affected Components</h4>
                    <div className="vuln-affected-list">
                        {summary.topAffected.map((a) => (
                            <div key={a.ref} className="vuln-affected-item">
                                <span className="vuln-affected-ref">{a.ref}</span>
                                <span className="vuln-affected-count">{a.count} vuln{a.count > 1 ? "s" : ""}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Vulnerability list */}
            <div className="vuln-list">
                <h4>All Vulnerabilities ({vulns.length})</h4>
                <div className="vuln-list-scroll">
                    {vulns.map((v) => {
                        const sev = getSeverity(v);
                        const score = getScore(v);
                        const isExpanded = expandedVuln === v.id;
                        return (
                            <div key={v.id} className={`vuln-item vuln-item-${sev}`}>
                                <div className="vuln-item-header" onClick={() => setExpandedVuln(isExpanded ? null : v.id)}>
                                    <span className={`vuln-sev-badge vuln-sev-bg-${sev}`}>{sev.toUpperCase()}</span>
                                    <span className="vuln-item-id">{v.id}</span>
                                    {score !== null && <span className="vuln-item-score">CVSS {score.toFixed(1)}</span>}
                                    <span className="vuln-item-arrow">{isExpanded ? "▼" : "▶"}</span>
                                </div>
                                {isExpanded && (
                                    <div className="vuln-item-detail fade-in">
                                        {v.source?.name && <div className="vuln-detail-row"><strong>Source:</strong> {v.source.name}</div>}
                                        {v.description && <div className="vuln-detail-row"><strong>Description:</strong> {v.description}</div>}
                                        {v.recommendation && <div className="vuln-detail-row"><strong>Recommendation:</strong> {v.recommendation}</div>}
                                        {v.cwes && v.cwes.length > 0 && (
                                            <div className="vuln-detail-row"><strong>CWEs:</strong> {v.cwes.map(c => `CWE-${c}`).join(", ")}</div>
                                        )}
                                        {v.affects && v.affects.length > 0 && (
                                            <div className="vuln-detail-row">
                                                <strong>Affects:</strong>
                                                {v.affects.map((a, i) => <code key={i} className="vuln-ref">{a.ref}</code>)}
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}
