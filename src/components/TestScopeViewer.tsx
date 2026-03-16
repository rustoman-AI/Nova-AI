import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Main Component ────────────────────────────────
export default function TestScopeViewer() {
    const [components, setComponents] = useState<any[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [filter, setFilter] = useState<"all" | "test" | "prod">("all");

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM with test scope properties",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setComponents(bom.components || []);
        setLoaded(true);
    }, []);

    const classified = useMemo(() => {
        return components.map(c => {
            const isTestProp = (c.properties || []).find((p: any) =>
                p.name === "cdx:gradle:isTest" || p.name === "cdx:npm:devDependency" || p.name === "cdx:maven:scope"
            );
            let scope: "test" | "prod" | "unknown" = "unknown";
            if (isTestProp) {
                const val = isTestProp.value?.toLowerCase();
                if (val === "true" || val === "test" || val === "provided") scope = "test";
                else scope = "prod";
            } else {
                // Heuristic: check component group/name for test indicators
                const name = (c.name || "").toLowerCase();
                const group = (c.group || "").toLowerCase();
                if (name.includes("test") || name.includes("mock") || name.includes("junit") ||
                    name.includes("assertj") || name.includes("hamcrest") || name.includes("spock") ||
                    group.includes("test") || group.includes("mock")) {
                    scope = "test";
                } else {
                    scope = "prod";
                }
            }
            return { ...c, _scope: scope, _scopeSource: isTestProp ? "property" : "heuristic" };
        });
    }, [components]);

    const stats = useMemo(() => {
        const test = classified.filter(c => c._scope === "test").length;
        const prod = classified.filter(c => c._scope === "prod").length;
        const unknown = classified.filter(c => c._scope === "unknown").length;
        return { test, prod, unknown, total: classified.length };
    }, [classified]);

    const filtered = useMemo(() => {
        if (filter === "all") return classified;
        return classified.filter(c => c._scope === filter);
    }, [classified, filter]);

    const testPct = stats.total > 0 ? Math.round((stats.test / stats.total) * 100) : 0;
    const prodPct = stats.total > 0 ? Math.round((stats.prod / stats.total) * 100) : 0;

    return (
        <div className="tscope-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Test / Production Scope</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
            </div>

            {classified.length > 0 ? (
                <div className="tscope-content fade-in">
                    {/* Stats */}
                    <div className="analyze-stats">
                        <div className="analyze-stat-card" onClick={() => setFilter("prod")} style={{ cursor: "pointer", borderColor: filter === "prod" ? "#22c55e" : undefined }}>
                            <span className="analyze-stat-value" style={{ color: "#22c55e" }}>{stats.prod}</span>
                            <span className="analyze-stat-label">Production ({prodPct}%)</span>
                        </div>
                        <div className="analyze-stat-card" onClick={() => setFilter("test")} style={{ cursor: "pointer", borderColor: filter === "test" ? "#f59e0b" : undefined }}>
                            <span className="analyze-stat-value" style={{ color: "#f59e0b" }}>{stats.test}</span>
                            <span className="analyze-stat-label">Test ({testPct}%)</span>
                        </div>
                        <div className="analyze-stat-card" onClick={() => setFilter("all")} style={{ cursor: "pointer", borderColor: filter === "all" ? "var(--accent)" : undefined }}>
                            <span className="analyze-stat-value">{stats.total}</span>
                            <span className="analyze-stat-label">Total</span>
                        </div>
                    </div>

                    {/* Scope bar */}
                    <div className="vex-status-bar" style={{ height: 14 }}>
                        <div className="vex-status-seg" style={{ width: `${prodPct}%`, background: "#22c55e" }} title={`Production: ${stats.prod}`} />
                        <div className="vex-status-seg" style={{ width: `${testPct}%`, background: "#f59e0b" }} title={`Test: ${stats.test}`} />
                    </div>

                    {/* Table */}
                    <div className="lic-table-wrap" style={{ flex: 1, overflow: "auto" }}>
                        <table className="lic-table">
                            <thead>
                                <tr>
                                    <th>Scope</th>
                                    <th>Component</th>
                                    <th>Version</th>
                                    <th>Type</th>
                                    <th>Source</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((c, i) => (
                                    <tr key={i}>
                                        <td>
                                            <span className={`tscope-badge tscope-${c._scope}`}>
                                                {c._scope === "test" ? "🧪 test" : c._scope === "prod" ? "🚀 prod" : "❓"}
                                            </span>
                                        </td>
                                        <td className="lic-id">{c.group ? `${c.group}/` : ""}{c.name || "?"}</td>
                                        <td>{c.version || "—"}</td>
                                        <td>{c.type || "—"}</td>
                                        <td><span className="prov-mini">{c._scopeSource}</span></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🧪</span>
                    <h3>Test / Production Scope</h3>
                    <p>Open a CycloneDX BOM to classify components as test or production dependencies</p>
                    <p style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Reads <code>cdx:gradle:isTest</code>, <code>cdx:maven:scope</code>, <code>cdx:npm:devDependency</code> properties, falls back to heuristic detection</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM has no components</p>}
                </div>
            )}
        </div>
    );
}
