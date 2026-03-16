import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface BomComponent {
    type?: string;
    name?: string;
    version?: string;
    group?: string;
    purl?: string;
    licenses?: { license?: { id?: string; name?: string } }[];
    hashes?: { alg?: string; content?: string }[];
}

interface Bom {
    bomFormat?: string;
    specVersion?: string;
    serialNumber?: string;
    version?: number;
    metadata?: { component?: BomComponent; timestamp?: string };
    components?: BomComponent[];
}

interface AnalysisData {
    bom: Bom;
    componentsByType: Record<string, number>;
    licenses: Record<string, number>;
    duplicates: { name: string; versions: string[] }[];
    totalComponents: number;
    withHashes: number;
    withPurl: number;
}

// ─── SVG Pie Chart ─────────────────────────────────
const COLORS = [
    "#6366f1", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6",
    "#ec4899", "#14b8a6", "#f97316", "#06b6d4", "#a855f7",
];

function PieChart({ data, title }: { data: Record<string, number>; title: string }) {
    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, v]) => s + v, 0);
    if (total === 0) return null;

    let cumulative = 0;
    const slices = entries.map(([label, value], i) => {
        const start = cumulative / total;
        cumulative += value;
        const end = cumulative / total;
        const startAngle = start * 2 * Math.PI - Math.PI / 2;
        const endAngle = end * 2 * Math.PI - Math.PI / 2;
        const largeArc = end - start > 0.5 ? 1 : 0;
        const x1 = 50 + 40 * Math.cos(startAngle);
        const y1 = 50 + 40 * Math.sin(startAngle);
        const x2 = 50 + 40 * Math.cos(endAngle);
        const y2 = 50 + 40 * Math.sin(endAngle);
        const color = COLORS[i % COLORS.length];
        const pct = ((value / total) * 100).toFixed(1);

        return {
            label, value, color, pct, path: entries.length === 1
                ? `M 50 10 A 40 40 0 1 1 49.99 10 Z`
                : `M 50 50 L ${x1} ${y1} A 40 40 0 ${largeArc} 1 ${x2} ${y2} Z`
        };
    });

    return (
        <div className="analyze-chart">
            <h4>{title}</h4>
            <div className="analyze-chart-row">
                <svg viewBox="0 0 100 100" className="analyze-pie">
                    {slices.map((s, i) => (
                        <path key={i} d={s.path} fill={s.color} stroke="var(--bg-card)" strokeWidth="0.5">
                            <title>{s.label}: {s.value} ({s.pct}%)</title>
                        </path>
                    ))}
                </svg>
                <div className="analyze-legend">
                    {slices.slice(0, 8).map((s, i) => (
                        <div key={i} className="analyze-legend-item">
                            <span className="analyze-legend-dot" style={{ background: s.color }} />
                            <span className="analyze-legend-label">{s.label}</span>
                            <span className="analyze-legend-value">{s.value} ({s.pct}%)</span>
                        </div>
                    ))}
                    {slices.length > 8 && (
                        <div className="analyze-legend-item">
                            <span className="analyze-legend-dot" style={{ background: "#666" }} />
                            <span className="analyze-legend-label">+{slices.length - 8} more</span>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// ─── Main Component ────────────────────────────────
export default function AnalyzeDashboard() {
    const [analysis, setAnalysis] = useState<AnalysisData | null>(null);
    const [bomPath, setBomPath] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM file",
        });
        if (!f) return;
        setBomPath(f as string);
        setIsLoading(true);
        try {
            const content = await invoke<string>("read_file_contents", { path: f as string });
            const bom: Bom = JSON.parse(content);
            const components = bom.components || [];

            // Component types
            const componentsByType: Record<string, number> = {};
            for (const c of components) {
                const t = c.type || "unknown";
                componentsByType[t] = (componentsByType[t] || 0) + 1;
            }

            // Licenses
            const licenses: Record<string, number> = {};
            for (const c of components) {
                const lics = c.licenses || [];
                if (lics.length === 0) {
                    licenses["none"] = (licenses["none"] || 0) + 1;
                } else {
                    for (const l of lics) {
                        const id = l.license?.id || l.license?.name || "unknown";
                        licenses[id] = (licenses[id] || 0) + 1;
                    }
                }
            }

            // Duplicate versions
            const byName: Record<string, Set<string>> = {};
            for (const c of components) {
                const key = c.group ? `${c.group}/${c.name}` : (c.name || "?");
                if (!byName[key]) byName[key] = new Set();
                if (c.version) byName[key].add(c.version);
            }
            const duplicates = Object.entries(byName)
                .filter(([, v]) => v.size > 1)
                .map(([name, versions]) => ({ name, versions: [...versions].sort() }))
                .sort((a, b) => b.versions.length - a.versions.length);

            // Stats
            const withHashes = components.filter(c => c.hashes && c.hashes.length > 0).length;
            const withPurl = components.filter(c => c.purl).length;

            setAnalysis({
                bom, componentsByType, licenses, duplicates,
                totalComponents: components.length, withHashes, withPurl,
            });
        } catch (e) {
            console.error("BOM parse error:", e);
        }
        setIsLoading(false);
    }, []);

    // ─── Also run CLI analyze for multiple-versions ───
    const [cliOutput, setCliOutput] = useState("");
    const runCliAnalyze = useCallback(async () => {
        if (!bomPath) return;
        try {
            const res = await invoke<{ stdout: string; stderr: string; success: boolean }>(
                "run_sidecar", { name: "cyclonedx", args: ["analyze", "--input-file", bomPath, "--multiple-component-versions"] }
            );
            setCliOutput(res.stdout || res.stderr);
        } catch { }
    }, [bomPath]);

    const stats = useMemo(() => {
        if (!analysis) return null;
        const { totalComponents, withHashes, withPurl, duplicates } = analysis;
        const hashPct = totalComponents > 0 ? Math.round((withHashes / totalComponents) * 100) : 0;
        const purlPct = totalComponents > 0 ? Math.round((withPurl / totalComponents) * 100) : 0;
        return { totalComponents, withHashes, hashPct, withPurl, purlPct, dupCount: duplicates.length };
    }, [analysis]);

    return (
        <div className="analyze-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">BOM Analysis</h2>
                <button className="exec-btn" onClick={loadBom} disabled={isLoading}>
                    {isLoading ? <><span className="spinner" /> Loading...</> : "📁 Open BOM"}
                </button>
                {bomPath && (
                    <button className="preset-btn" onClick={runCliAnalyze}>🔍 CLI Analyze</button>
                )}
            </div>

            {stats && analysis && (
                <div className="analyze-content fade-in">
                    {/* Stats cards */}
                    <div className="analyze-stats">
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.totalComponents}</span>
                            <span className="analyze-stat-label">Components</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.hashPct}%</span>
                            <span className="analyze-stat-label">With Hashes ({stats.withHashes})</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.purlPct}%</span>
                            <span className="analyze-stat-label">With PURL ({stats.withPurl})</span>
                        </div>
                        <div className={`analyze-stat-card ${stats.dupCount > 0 ? "analyze-stat-warn" : ""}`}>
                            <span className="analyze-stat-value">{stats.dupCount}</span>
                            <span className="analyze-stat-label">Duplicate Versions</span>
                        </div>
                    </div>

                    {/* BOM metadata */}
                    {analysis.bom.metadata?.component && (
                        <div className="pipe-config" style={{ marginBottom: 12 }}>
                            <span className="pipe-config-item">📦 {analysis.bom.metadata.component.name} {analysis.bom.metadata.component.version}</span>
                            <span className="pipe-config-item">📋 Spec {analysis.bom.specVersion}</span>
                            {analysis.bom.serialNumber && <span className="pipe-config-item">🔢 {analysis.bom.serialNumber.slice(0, 20)}...</span>}
                        </div>
                    )}

                    {/* Charts row */}
                    <div className="analyze-charts-row">
                        <PieChart data={analysis.componentsByType} title="Component Types" />
                        <PieChart data={analysis.licenses} title="Licenses" />
                    </div>

                    {/* Duplicates */}
                    {analysis.duplicates.length > 0 && (
                        <div className="analyze-duplicates">
                            <h4>⚠️ Components with Multiple Versions ({analysis.duplicates.length})</h4>
                            <div className="analyze-dup-list">
                                {analysis.duplicates.slice(0, 20).map((d, i) => (
                                    <div key={i} className="analyze-dup-row">
                                        <span className="analyze-dup-name">{d.name}</span>
                                        <div className="analyze-dup-versions">
                                            {d.versions.map((v, j) => (
                                                <span key={j} className="analyze-dup-badge">{v}</span>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* CLI output */}
                    {cliOutput && (
                        <div className="crypto-result crypto-result-ok">
                            <div className="crypto-result-header">CLI Analyze Output</div>
                            <pre className="crypto-result-text">{cliOutput}</pre>
                        </div>
                    )}
                </div>
            )}

            {!analysis && !isLoading && (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📊</span>
                    <h3>BOM Analysis Dashboard</h3>
                    <p>Open a CycloneDX BOM file to see component types, licenses, and quality metrics</p>
                </div>
            )}
        </div>
    );
}
