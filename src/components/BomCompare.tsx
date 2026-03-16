import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface CompInfo {
    key: string; // purl or group/name
    name: string;
    version?: string;
    licenses: string[];
    hasHash: boolean;
    hasPurl: boolean;
    type?: string;
}

interface DiffResult {
    added: CompInfo[];
    removed: CompInfo[];
    versionChanged: { left: CompInfo; right: CompInfo }[];
    licenseChanged: { left: CompInfo; right: CompInfo }[];
    unchanged: number;
}

function extractComponents(bom: any): Map<string, CompInfo> {
    const m = new Map<string, CompInfo>();
    for (const c of (bom.components || [])) {
        const key = c.purl || `${c.group || ""}/${c.name || "?"}`;
        const lics = (c.licenses || []).map((l: any) => l.license?.id || l.expression || "?");
        m.set(key, {
            key, name: c.name || "?", version: c.version,
            licenses: lics, hasHash: !!(c.hashes?.length), hasPurl: !!c.purl, type: c.type,
        });
    }
    return m;
}

function diffBoms(left: Map<string, CompInfo>, right: Map<string, CompInfo>): DiffResult {
    const added: CompInfo[] = [];
    const removed: CompInfo[] = [];
    const versionChanged: { left: CompInfo; right: CompInfo }[] = [];
    const licenseChanged: { left: CompInfo; right: CompInfo }[] = [];
    let unchanged = 0;

    for (const [k, lc] of left) {
        const rc = right.get(k);
        if (!rc) { removed.push(lc); continue; }
        let changed = false;
        if (lc.version !== rc.version) { versionChanged.push({ left: lc, right: rc }); changed = true; }
        if (lc.licenses.join(",") !== rc.licenses.join(",")) { licenseChanged.push({ left: lc, right: rc }); changed = true; }
        if (!changed) unchanged++;
    }
    for (const [k, rc] of right) {
        if (!left.has(k)) added.push(rc);
    }
    return { added, removed, versionChanged, licenseChanged, unchanged };
}

// ─── Main Component ────────────────────────────────
export default function BomCompare() {
    const [leftName, setLeftName] = useState("");
    const [rightName, setRightName] = useState("");
    const [leftComps, setLeftComps] = useState<Map<string, CompInfo> | null>(null);
    const [rightComps, setRightComps] = useState<Map<string, CompInfo> | null>(null);
    const [leftMeta, setLeftMeta] = useState<any>(null);
    const [rightMeta, setRightMeta] = useState<any>(null);

    const loadSide = useCallback(async (side: "left" | "right") => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: `Select ${side === "left" ? "LEFT (old)" : "RIGHT (new)"} BOM`,
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        const comps = extractComponents(bom);
        const name = (f as string).split("/").pop() || "BOM";
        if (side === "left") { setLeftComps(comps); setLeftName(name); setLeftMeta(bom.metadata); }
        else { setRightComps(comps); setRightName(name); setRightMeta(bom.metadata); }
    }, []);

    const diff = useMemo(() => {
        if (!leftComps || !rightComps) return null;
        return diffBoms(leftComps, rightComps);
    }, [leftComps, rightComps]);

    const severity = diff ? (
        diff.removed.length > 0 || diff.versionChanged.length > 5 ? "breaking" :
            diff.added.length > 0 || diff.versionChanged.length > 0 ? "minor" : "none"
    ) : null;

    return (
        <div className="cmp-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">BOM Compare</h2>
                <div className="cmp-btns">
                    <button className="exec-btn" onClick={() => loadSide("left")}>📁 Left {leftName && `(${leftName})`}</button>
                    <span className="cmp-vs">⇄</span>
                    <button className="exec-btn" onClick={() => loadSide("right")}>📁 Right {rightName && `(${rightName})`}</button>
                </div>
            </div>

            {diff ? (
                <div className="cmp-content fade-in">
                    {/* Summary */}
                    <div className="analyze-stats">
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: "#22c55e" }}>+{diff.added.length}</span>
                            <span className="analyze-stat-label">Added</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: "#ef4444" }}>−{diff.removed.length}</span>
                            <span className="analyze-stat-label">Removed</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: "#f59e0b" }}>{diff.versionChanged.length}</span>
                            <span className="analyze-stat-label">Version Changed</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: "#8b5cf6" }}>{diff.licenseChanged.length}</span>
                            <span className="analyze-stat-label">License Changed</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{diff.unchanged}</span>
                            <span className="analyze-stat-label">Unchanged</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className={`cmp-severity cmp-severity-${severity}`}>
                                {severity === "breaking" ? "🔴 Breaking" : severity === "minor" ? "🟡 Minor" : "🟢 No changes"}
                            </span>
                        </div>
                    </div>

                    {/* Metadata comparison */}
                    {leftMeta && rightMeta && (
                        <div className="cmp-meta">
                            <div className="cmp-meta-side">
                                <b>{leftName}</b>
                                <div className="cmp-meta-row">Spec: {leftMeta.component?.specVersion || "?"}</div>
                                <div className="cmp-meta-row">Components: {leftComps?.size || 0}</div>
                                <div className="cmp-meta-row">Timestamp: {leftMeta.timestamp?.slice(0, 19) || "—"}</div>
                            </div>
                            <div className="cmp-meta-side">
                                <b>{rightName}</b>
                                <div className="cmp-meta-row">Spec: {rightMeta.component?.specVersion || "?"}</div>
                                <div className="cmp-meta-row">Components: {rightComps?.size || 0}</div>
                                <div className="cmp-meta-row">Timestamp: {rightMeta.timestamp?.slice(0, 19) || "—"}</div>
                            </div>
                        </div>
                    )}

                    {/* Added */}
                    {diff.added.length > 0 && (
                        <div className="cmp-section">
                            <h4>🟢 Added ({diff.added.length})</h4>
                            <div className="lic-table-wrap">
                                <table className="lic-table">
                                    <thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Licenses</th></tr></thead>
                                    <tbody>
                                        {diff.added.map((c, i) => (
                                            <tr key={i} className="cmp-row-added">
                                                <td className="lic-id">{c.name}</td>
                                                <td>{c.version || "—"}</td>
                                                <td>{c.type || "—"}</td>
                                                <td>{c.licenses.join(", ") || "—"}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Removed */}
                    {diff.removed.length > 0 && (
                        <div className="cmp-section">
                            <h4>🔴 Removed ({diff.removed.length})</h4>
                            <div className="lic-table-wrap">
                                <table className="lic-table">
                                    <thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Licenses</th></tr></thead>
                                    <tbody>
                                        {diff.removed.map((c, i) => (
                                            <tr key={i} className="cmp-row-removed">
                                                <td className="lic-id">{c.name}</td>
                                                <td>{c.version || "—"}</td>
                                                <td>{c.type || "—"}</td>
                                                <td>{c.licenses.join(", ") || "—"}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Version changed */}
                    {diff.versionChanged.length > 0 && (
                        <div className="cmp-section">
                            <h4>🟡 Version Changed ({diff.versionChanged.length})</h4>
                            <div className="lic-table-wrap">
                                <table className="lic-table">
                                    <thead><tr><th>Component</th><th>Old Version</th><th>→</th><th>New Version</th></tr></thead>
                                    <tbody>
                                        {diff.versionChanged.map((c, i) => (
                                            <tr key={i} className="cmp-row-changed">
                                                <td className="lic-id">{c.left.name}</td>
                                                <td className="cmp-old">{c.left.version || "—"}</td>
                                                <td>→</td>
                                                <td className="cmp-new">{c.right.version || "—"}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* License changed */}
                    {diff.licenseChanged.length > 0 && (
                        <div className="cmp-section">
                            <h4>🟣 License Changed ({diff.licenseChanged.length})</h4>
                            <div className="lic-table-wrap">
                                <table className="lic-table">
                                    <thead><tr><th>Component</th><th>Old Licenses</th><th>→</th><th>New Licenses</th></tr></thead>
                                    <tbody>
                                        {diff.licenseChanged.map((c, i) => (
                                            <tr key={i} className="cmp-row-changed">
                                                <td className="lic-id">{c.left.name}</td>
                                                <td className="cmp-old">{c.left.licenses.join(", ") || "—"}</td>
                                                <td>→</td>
                                                <td className="cmp-new">{c.right.licenses.join(", ") || "—"}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">⚖️</span>
                    <h3>BOM Comparison</h3>
                    <p>Select two CycloneDX BOMs to compare: added, removed, version-changed, and license-changed components</p>
                </div>
            )}
        </div>
    );
}
