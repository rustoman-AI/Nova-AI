import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface IdentityEntry {
    field?: string;
    confidence?: number;
    concludedValue?: string;
    methods?: { technique?: string; confidence?: number; value?: string }[];
}

interface Occurrence {
    "bom-ref"?: string;
    location?: string;
    line?: number;
    offset?: number;
    symbol?: string;
    additionalContext?: string;
}

interface CallstackFrame {
    module?: string;
    function?: string;
    fullFilename?: string;
    line?: number;
    column?: number;
    package?: string;
}

interface ComponentEvidence {
    componentName: string;
    componentRef?: string;
    identity?: IdentityEntry[];
    occurrences?: Occurrence[];
    callstack?: { frames?: CallstackFrame[] };
}

function confidenceLabel(c: number): { label: string; cls: string } {
    if (c >= 0.8) return { label: "High", cls: "ev-conf-high" };
    if (c >= 0.5) return { label: "Medium", cls: "ev-conf-med" };
    return { label: "Low", cls: "ev-conf-low" };
}

// ─── Main Component ────────────────────────────────
export default function EvidencePanel() {
    const [items, setItems] = useState<ComponentEvidence[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [selected, setSelected] = useState<ComponentEvidence | null>(null);
    const [expandedFrames, setExpandedFrames] = useState<Set<string>>(new Set());

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM file",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        const components: any[] = bom.components || [];

        const result: ComponentEvidence[] = [];
        for (const c of components) {
            const ev = c.evidence;
            if (!ev) continue;
            const name = c.group ? `${c.group}/${c.name}` : (c.name || "?");
            result.push({
                componentName: name,
                componentRef: c["bom-ref"],
                identity: ev.identity || [],
                occurrences: ev.occurrences || [],
                callstack: ev.callstack || null,
            });
        }
        setItems(result);
        setLoaded(true);
        setSelected(null);
        setExpandedFrames(new Set());
    }, []);

    const toggleFrame = useCallback((id: string) => {
        setExpandedFrames(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
    }, []);

    const stats = useMemo(() => {
        let identities = 0, occurrences = 0, callstacks = 0;
        let sumConf = 0, confCount = 0;
        for (const it of items) {
            identities += (it.identity || []).length;
            occurrences += (it.occurrences || []).length;
            if (it.callstack?.frames?.length) callstacks++;
            for (const id of it.identity || []) {
                if (id.confidence !== undefined) { sumConf += id.confidence; confCount++; }
            }
        }
        const avgConf = confCount > 0 ? Math.round((sumConf / confCount) * 100) : 0;
        return { total: items.length, identities, occurrences, callstacks, avgConf };
    }, [items]);

    const hasData = items.length > 0;

    return (
        <div className="ev-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Component Evidence</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {hasData && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{stats.total} components</span>
                        <span className="depgraph-stat">{stats.identities} identities</span>
                        <span className="depgraph-stat">{stats.occurrences} occurrences</span>
                        <span className="depgraph-stat">{stats.callstacks} callstacks</span>
                        <span className="depgraph-stat" style={{
                            color: stats.avgConf >= 80 ? "#22c55e" : stats.avgConf >= 50 ? "#f59e0b" : "#ef4444",
                            borderColor: stats.avgConf >= 80 ? "#22c55e" : stats.avgConf >= 50 ? "#f59e0b" : "#ef4444",
                        }}>Avg conf: {stats.avgConf}%</span>
                    </div>
                )}
            </div>

            {hasData ? (
                <div className="ev-content fade-in">
                    <div className="svc-list-and-detail">
                        {/* Component list with confidence heatmap */}
                        <div className="svc-list">
                            {items.map((it, i) => {
                                const maxConf = Math.max(...(it.identity || []).map(id => id.confidence || 0), 0);
                                const { cls } = confidenceLabel(maxConf);
                                const isActive = selected === it;
                                return (
                                    <div key={i}
                                        className={`svc-node-header ${isActive ? "svc-node-active" : ""}`}
                                        onClick={() => setSelected(it)}
                                    >
                                        <span className={`ev-conf-dot ${cls}`} />
                                        <span className="svc-node-name">{it.componentName}</span>
                                        <span className="svc-mini-badge">{(it.identity || []).length} id</span>
                                        {(it.occurrences || []).length > 0 && (
                                            <span className="svc-mini-badge svc-mini-data">{it.occurrences!.length} occ</span>
                                        )}
                                        {it.callstack?.frames?.length && (
                                            <span className="svc-mini-badge svc-mini-auth">📚 stack</span>
                                        )}
                                    </div>
                                );
                            })}
                        </div>

                        {/* Detail panel */}
                        {selected && (
                            <div className="svc-detail fade-in" style={{ width: 420 }}>
                                <div className="svc-detail-header">
                                    <h3>{selected.componentName}</h3>
                                    <button className="merge-file-rm" onClick={() => setSelected(null)}>✕</button>
                                </div>

                                {/* Identity table */}
                                {selected.identity && selected.identity.length > 0 && (
                                    <div className="ev-section">
                                        <b>🆔 Identity ({selected.identity.length})</b>
                                        <div className="lic-table-wrap" style={{ marginTop: 4 }}>
                                            <table className="lic-table">
                                                <thead><tr><th>Field</th><th>Value</th><th>Confidence</th><th>Methods</th></tr></thead>
                                                <tbody>
                                                    {selected.identity.map((id, i) => {
                                                        const conf = id.confidence !== undefined ? confidenceLabel(id.confidence) : null;
                                                        return (
                                                            <tr key={i}>
                                                                <td className="lic-id">{id.field || "—"}</td>
                                                                <td>{id.concludedValue || "—"}</td>
                                                                <td>
                                                                    {conf ? (
                                                                        <span className={`ev-conf-badge ${conf.cls}`}>
                                                                            {Math.round((id.confidence || 0) * 100)}% {conf.label}
                                                                        </span>
                                                                    ) : "—"}
                                                                </td>
                                                                <td>
                                                                    {(id.methods || []).map((m, j) => (
                                                                        <span key={j} className="ev-method">{m.technique || "?"}</span>
                                                                    ))}
                                                                    {(!id.methods || id.methods.length === 0) && "—"}
                                                                </td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}

                                {/* Occurrences */}
                                {selected.occurrences && selected.occurrences.length > 0 && (
                                    <div className="ev-section">
                                        <b>📍 Occurrences ({selected.occurrences.length})</b>
                                        <div className="ev-occ-list">
                                            {selected.occurrences.map((occ, i) => (
                                                <div key={i} className="ev-occ-item">
                                                    <code className="ev-occ-loc">{occ.location || "?"}</code>
                                                    {occ.line !== undefined && <span className="ev-occ-line">:{occ.line}</span>}
                                                    {occ.offset !== undefined && <span className="ev-occ-line">+{occ.offset}</span>}
                                                    {occ.symbol && <span className="ev-occ-sym">{occ.symbol}</span>}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Callstack */}
                                {selected.callstack?.frames && selected.callstack.frames.length > 0 && (
                                    <div className="ev-section">
                                        <b>📚 Callstack ({selected.callstack.frames.length} frames)</b>
                                        <div className="ev-stack">
                                            {selected.callstack.frames.map((frame, i) => {
                                                const fid = `${selected.componentRef}-${i}`;
                                                const isExp = expandedFrames.has(fid);
                                                return (
                                                    <div key={i} className="ev-frame" onClick={() => toggleFrame(fid)}>
                                                        <div className="ev-frame-header">
                                                            <span className="ev-frame-num">#{i}</span>
                                                            <span className="ev-frame-fn">{frame.function || frame.module || "?"}</span>
                                                            {frame.fullFilename && (
                                                                <code className="ev-frame-file">{frame.fullFilename}{frame.line !== undefined ? `:${frame.line}` : ""}</code>
                                                            )}
                                                        </div>
                                                        {isExp && (
                                                            <div className="ev-frame-detail">
                                                                {frame.module && <div>Module: {frame.module}</div>}
                                                                {frame.package && <div>Package: {frame.package}</div>}
                                                                {frame.column !== undefined && <div>Column: {frame.column}</div>}
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🧬</span>
                    <h3>Component Evidence</h3>
                    <p>Open a CycloneDX BOM with <code>components[].evidence</code> to view identity confidence, occurrences, and callstacks</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM does not contain component evidence data</p>}
                </div>
            )}
        </div>
    );
}
