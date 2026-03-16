import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface Requirement {
    "bom-ref"?: string;
    identifier?: string;
    title?: string;
    text?: string;
    descriptions?: string[];
    externalReferences?: { url?: string; type?: string }[];
    parent?: string;
    requirements?: Requirement[];
}

interface Standard {
    "bom-ref"?: string;
    name?: string;
    version?: string;
    description?: string;
    owner?: string;
    requirements?: Requirement[];
    externalReferences?: { url?: string; type?: string }[];
}

// ─── Recursive Requirement Node ────────────────────
function ReqNode({ req, depth }: { req: Requirement; depth: number }) {
    const [expanded, setExpanded] = useState(depth < 2);
    const hasChildren = req.requirements && req.requirements.length > 0;

    return (
        <div className="std-req-node" style={{ marginLeft: depth * 14 }}>
            <div className="std-req-header" onClick={() => hasChildren && setExpanded(!expanded)}>
                {hasChildren && <span className="merge-node-toggle">{expanded ? "▼" : "▶"}</span>}
                <span className="std-req-id">{req.identifier || req["bom-ref"] || "?"}</span>
                <span className="std-req-title">{req.title || ""}</span>
            </div>
            {req.text && <div className="std-req-text">{req.text}</div>}
            {expanded && hasChildren && (
                <div className="std-req-children">
                    {req.requirements!.map((child, i) => (
                        <ReqNode key={i} req={child} depth={depth + 1} />
                    ))}
                </div>
            )}
        </div>
    );
}

// ─── Main Component ────────────────────────────────
export default function StandardsViewer() {
    const [standards, setStandards] = useState<Standard[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [selectedStd, setSelectedStd] = useState<Standard | null>(null);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM with definitions.standards",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setStandards(bom.definitions?.standards || []);
        setLoaded(true);
        setSelectedStd(null);
    }, []);

    const hasData = standards.length > 0;

    return (
        <div className="std-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Standards & Definitions</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {hasData && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{standards.length} standards</span>
                        <span className="depgraph-stat">
                            {standards.reduce((s, st) => s + (st.requirements?.length || 0), 0)} requirements
                        </span>
                    </div>
                )}
            </div>

            {hasData ? (
                <div className="std-content fade-in">
                    <div className="svc-list-and-detail">
                        {/* Standards list */}
                        <div className="svc-list">
                            {standards.map((st, i) => {
                                const isActive = selectedStd === st;
                                return (
                                    <div key={i}
                                        className={`svc-node-header ${isActive ? "svc-node-active" : ""}`}
                                        onClick={() => setSelectedStd(st)}
                                    >
                                        <span className="std-std-icon">📐</span>
                                        <span className="svc-node-name">{st.name || st["bom-ref"] || `#${i + 1}`}</span>
                                        {st.version && <span className="svc-node-ver">{st.version}</span>}
                                        <span className="svc-mini-badge">{st.requirements?.length || 0} reqs</span>
                                    </div>
                                );
                            })}
                        </div>

                        {/* Detail panel */}
                        {selectedStd && (
                            <div className="svc-detail fade-in" style={{ width: 450, overflow: "auto" }}>
                                <div className="svc-detail-header">
                                    <h3>{selectedStd.name || "?"}</h3>
                                    <button className="merge-file-rm" onClick={() => setSelectedStd(null)}>✕</button>
                                </div>
                                {selectedStd.version && <div className="svc-detail-row"><b>Version:</b> {selectedStd.version}</div>}
                                {selectedStd.owner && <div className="svc-detail-row"><b>Owner:</b> {selectedStd.owner}</div>}
                                {selectedStd.description && <div className="svc-detail-row">{selectedStd.description}</div>}

                                {selectedStd.externalReferences && selectedStd.externalReferences.length > 0 && (
                                    <div className="ev-section">
                                        <b>🔗 External References</b>
                                        {selectedStd.externalReferences.map((r, i) => (
                                            <div key={i} className="std-ext-ref">{r.type}: {r.url}</div>
                                        ))}
                                    </div>
                                )}

                                {/* Requirements tree */}
                                {selectedStd.requirements && selectedStd.requirements.length > 0 && (
                                    <div className="ev-section">
                                        <b>📋 Requirements ({selectedStd.requirements.length})</b>
                                        <div className="std-req-tree">
                                            {selectedStd.requirements.map((req, i) => (
                                                <ReqNode key={i} req={req} depth={0} />
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📐</span>
                    <h3>Standards & Definitions</h3>
                    <p>Open a CycloneDX 1.6+ BOM with <code>definitions.standards[]</code> to view standards, requirements, and external references</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM does not contain definitions.standards data</p>}
                </div>
            )}
        </div>
    );
}
