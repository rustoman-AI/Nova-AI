import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

const TYPE_ICONS: Record<string, string> = {
    vcs: "🔗", website: "🌐", "issue-tracker": "🐛", "mailing-list": "📧",
    "build-system": "🏗️", distribution: "📦", documentation: "📖", license: "🏷️",
    chat: "💬", support: "🆘", advisories: "⚠️", bom: "📋",
    "release-notes": "📝", other: "📎",
};

interface ExtRef {
    type: string;
    url: string;
    comment?: string;
    componentName?: string;
    level: "metadata" | "component" | "service";
}

export default function ExternalRefsExplorer() {
    const [refs, setRefs] = useState<ExtRef[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [filterType, setFilterType] = useState<string | null>(null);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        const result: ExtRef[] = [];

        // Metadata level
        for (const r of (bom.metadata?.component?.externalReferences || [])) {
            result.push({ type: r.type || "other", url: r.url || "", comment: r.comment, level: "metadata" });
        }
        for (const r of (bom.externalReferences || [])) {
            result.push({ type: r.type || "other", url: r.url || "", comment: r.comment, level: "metadata" });
        }
        // Component level
        for (const c of (bom.components || [])) {
            for (const r of (c.externalReferences || [])) {
                const name = c.group ? `${c.group}/${c.name}` : (c.name || "?");
                result.push({ type: r.type || "other", url: r.url || "", comment: r.comment, componentName: name, level: "component" });
            }
        }
        // Service level
        for (const s of (bom.services || [])) {
            for (const r of (s.externalReferences || [])) {
                result.push({ type: r.type || "other", url: r.url || "", comment: r.comment, componentName: s.name, level: "service" });
            }
        }
        setRefs(result);
        setLoaded(true);
    }, []);

    const typeCounts = useMemo(() => {
        const m = new Map<string, number>();
        for (const r of refs) m.set(r.type, (m.get(r.type) || 0) + 1);
        return [...m].sort((a, b) => b[1] - a[1]);
    }, [refs]);

    const filtered = useMemo(() => {
        if (!filterType) return refs;
        return refs.filter(r => r.type === filterType);
    }, [refs, filterType]);

    const coverageStats = useMemo(() => {
        const types = new Set(refs.map(r => r.type));
        const importantTypes = ["vcs", "website", "issue-tracker", "documentation", "build-system", "license"];
        const covered = importantTypes.filter(t => types.has(t));
        return { covered: covered.length, total: importantTypes.length, missing: importantTypes.filter(t => !types.has(t)) };
    }, [refs]);

    return (
        <div className="extref-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">External References</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {refs.length > 0 && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{refs.length} references</span>
                        <span className="depgraph-stat">{typeCounts.length} types</span>
                        <span className="depgraph-stat" style={{
                            color: coverageStats.covered === coverageStats.total ? "#22c55e" : "#f59e0b"
                        }}>Coverage: {coverageStats.covered}/{coverageStats.total}</span>
                    </div>
                )}
            </div>

            {refs.length > 0 ? (
                <div className="extref-content fade-in">
                    {/* Type pills */}
                    <div className="extref-types">
                        <span className={`extref-type-pill ${!filterType ? "extref-type-active" : ""}`} onClick={() => setFilterType(null)}>
                            All ({refs.length})
                        </span>
                        {typeCounts.map(([type, cnt]) => (
                            <span key={type}
                                className={`extref-type-pill ${filterType === type ? "extref-type-active" : ""}`}
                                onClick={() => setFilterType(filterType === type ? null : type)}
                            >
                                {TYPE_ICONS[type] || "📎"} {type} ({cnt})
                            </span>
                        ))}
                    </div>

                    {/* Missing coverage */}
                    {coverageStats.missing.length > 0 && (
                        <div className="extref-missing">
                            💡 Missing: {coverageStats.missing.map(t => `${TYPE_ICONS[t] || ""} ${t}`).join(", ")}
                        </div>
                    )}

                    {/* Table */}
                    <div className="lic-table-wrap" style={{ flex: 1, overflow: "auto" }}>
                        <table className="lic-table">
                            <thead><tr><th>Type</th><th>URL</th><th>Source</th><th>Level</th></tr></thead>
                            <tbody>
                                {filtered.map((r, i) => (
                                    <tr key={i}>
                                        <td><span className="extref-type-badge">{TYPE_ICONS[r.type] || "📎"} {r.type}</span></td>
                                        <td className="extref-url">{r.url}</td>
                                        <td className="lic-id">{r.componentName || "—"}</td>
                                        <td><span className={`prov-mini prov-mini-${r.level}`}>{r.level}</span></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🔗</span>
                    <h3>External References</h3>
                    <p>Open a CycloneDX BOM to explore all external references: VCS, websites, issue trackers, documentation, build systems, and more</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ No external references found</p>}
                </div>
            )}
        </div>
    );
}
