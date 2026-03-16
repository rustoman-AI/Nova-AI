import { useState, useCallback, useMemo, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface BomComponent {
    type?: string;
    name?: string;
    version?: string;
    group?: string;
    purl?: string;
    "bom-ref"?: string;
    hashes?: { alg?: string; content?: string }[];
    licenses?: { license?: { id?: string; name?: string } }[];
}

interface BomDep {
    ref: string;
    dependsOn?: string[];
}

interface Bom {
    metadata?: { component?: BomComponent };
    components?: BomComponent[];
    dependencies?: BomDep[];
}

interface GraphNode {
    id: string;
    label: string;
    fullName: string;
    version: string;
    type: string;
    purl: string;
    hashes: { alg?: string; content?: string }[];
    licenses: string[];
    x: number;
    y: number;
    vx: number;
    vy: number;
    isOrphan: boolean;
}

interface GraphEdge {
    source: string;
    target: string;
}

// ─── Colors by type ────────────────────────────────
const TYPE_COLORS: Record<string, string> = {
    library: "#6366f1",
    framework: "#8b5cf6",
    application: "#22c55e",
    file: "#f59e0b",
    firmware: "#ef4444",
    device: "#ec4899",
    container: "#14b8a6",
    "operating-system": "#f97316",
    data: "#06b6d4",
};
const DEFAULT_COLOR = "#64748b";

// ─── Force simulation (simple spring model) ────────
function simulate(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number, iterations = 120) {
    const nodeMap = new Map(nodes.map(n => [n.id, n]));

    // Init positions in a circle
    nodes.forEach((n, i) => {
        const angle = (2 * Math.PI * i) / nodes.length;
        const r = Math.min(width, height) * 0.35;
        n.x = width / 2 + r * Math.cos(angle);
        n.y = height / 2 + r * Math.sin(angle);
        n.vx = 0;
        n.vy = 0;
    });

    for (let iter = 0; iter < iterations; iter++) {
        const alpha = 1 - iter / iterations;
        const repulsion = 1200 * alpha;
        const attraction = 0.008 * alpha;
        const centerPull = 0.01 * alpha;

        // Repulsion (charge)
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const a = nodes[i], b = nodes[j];
                let dx = b.x - a.x, dy = b.y - a.y;
                const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
                const force = repulsion / (dist * dist);
                const fx = (dx / dist) * force, fy = (dy / dist) * force;
                a.vx -= fx; a.vy -= fy;
                b.vx += fx; b.vy += fy;
            }
        }

        // Attraction (springs)
        for (const e of edges) {
            const a = nodeMap.get(e.source), b = nodeMap.get(e.target);
            if (!a || !b) continue;
            const dx = b.x - a.x, dy = b.y - a.y;
            const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
            const force = (dist - 80) * attraction;
            const fx = (dx / dist) * force, fy = (dy / dist) * force;
            a.vx += fx; a.vy += fy;
            b.vx -= fx; b.vy -= fy;
        }

        // Center pull
        for (const n of nodes) {
            n.vx += (width / 2 - n.x) * centerPull;
            n.vy += (height / 2 - n.y) * centerPull;
        }

        // Apply velocities with damping
        for (const n of nodes) {
            n.vx *= 0.85; n.vy *= 0.85;
            n.x += n.vx; n.y += n.vy;
            n.x = Math.max(20, Math.min(width - 20, n.x));
            n.y = Math.max(20, Math.min(height - 20, n.y));
        }
    }
}

// ─── Main Component ────────────────────────────────
export default function DependencyGraph() {
    const [nodes, setNodes] = useState<GraphNode[]>([]);
    const [edges, setEdges] = useState<GraphEdge[]>([]);
    const [selected, setSelected] = useState<GraphNode | null>(null);
    const [hovered, setHovered] = useState<string | null>(null);
    const [search, setSearch] = useState("");
    const svgRef = useRef<SVGSVGElement>(null);
    const [dims] = useState({ w: 1200, h: 800 });

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM file",
        });
        if (!f) return;
        setSelected(null);

        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom: Bom = JSON.parse(content);
        const components = bom.components || [];
        const deps = bom.dependencies || [];

        // Build ref→component map
        const refMap = new Map<string, BomComponent>();
        if (bom.metadata?.component?.["bom-ref"]) {
            refMap.set(bom.metadata.component["bom-ref"], bom.metadata.component);
        }
        for (const c of components) {
            if (c["bom-ref"]) refMap.set(c["bom-ref"], c);
        }

        // Build edges
        const edgeList: GraphEdge[] = [];
        const refsInGraph = new Set<string>();
        for (const d of deps) {
            refsInGraph.add(d.ref);
            for (const t of d.dependsOn || []) {
                refsInGraph.add(t);
                edgeList.push({ source: d.ref, target: t });
            }
        }

        // Build nodes
        const nodeList: GraphNode[] = [];
        for (const [ref, comp] of refMap) {
            const fullName = comp.group ? `${comp.group}/${comp.name}` : (comp.name || ref);
            nodeList.push({
                id: ref,
                label: (comp.name || ref).slice(0, 24),
                fullName,
                version: comp.version || "",
                type: comp.type || "library",
                purl: comp.purl || "",
                hashes: comp.hashes || [],
                licenses: (comp.licenses || []).map(l => l.license?.id || l.license?.name || "unknown"),
                x: 0, y: 0, vx: 0, vy: 0,
                isOrphan: !refsInGraph.has(ref),
            });
        }

        // Simulate
        simulate(nodeList, edgeList, dims.w, dims.h, Math.min(200, nodeList.length * 3));

        setNodes(nodeList);
        setEdges(edgeList);
    }, [dims]);

    // Hover highlights: find all transitive deps
    const transitiveDeps = useMemo(() => {
        if (!hovered) return new Set<string>();
        const adj = new Map<string, string[]>();
        for (const e of edges) {
            if (!adj.has(e.source)) adj.set(e.source, []);
            adj.get(e.source)!.push(e.target);
        }
        const visited = new Set<string>();
        const queue = [hovered];
        while (queue.length) {
            const cur = queue.pop()!;
            if (visited.has(cur)) continue;
            visited.add(cur);
            for (const next of adj.get(cur) || []) queue.push(next);
        }
        return visited;
    }, [hovered, edges]);

    // Search filter
    const searchLower = search.toLowerCase();
    const filteredNodes = useMemo(() =>
        search ? nodes.filter(n => n.fullName.toLowerCase().includes(searchLower) || n.purl.toLowerCase().includes(searchLower)) : nodes,
        [nodes, searchLower, search]);
    const filteredIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

    // Stats
    const orphanCount = useMemo(() => nodes.filter(n => n.isOrphan).length, [nodes]);

    // Zoom state
    const [zoom, setZoom] = useState(1);
    const [pan, setPan] = useState({ x: 0, y: 0 });
    const isPanning = useRef(false);
    const panStart = useRef({ x: 0, y: 0, px: 0, py: 0 });

    const handleWheel = useCallback((e: React.WheelEvent) => {
        e.preventDefault();
        setZoom(z => Math.max(0.2, Math.min(5, z - e.deltaY * 0.001)));
    }, []);

    const handleMouseDown = useCallback((e: React.MouseEvent) => {
        if (e.button === 1 || e.button === 0 && e.shiftKey) {
            isPanning.current = true;
            panStart.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
        }
    }, [pan]);

    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        if (isPanning.current) {
            setPan({
                x: panStart.current.px + (e.clientX - panStart.current.x),
                y: panStart.current.py + (e.clientY - panStart.current.y),
            });
        }
    }, []);

    const handleMouseUp = useCallback(() => { isPanning.current = false; }, []);

    return (
        <div className="depgraph-panel">
            <div className="depgraph-header">
                <h2 className="pipe-title">Dependency Graph</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {nodes.length > 0 && (
                    <>
                        <input
                            className="settings-input depgraph-search"
                            placeholder="🔍 Search component..."
                            value={search}
                            onChange={e => setSearch(e.target.value)}
                        />
                        <div className="depgraph-stats">
                            <span className="depgraph-stat">{nodes.length} nodes</span>
                            <span className="depgraph-stat">{edges.length} edges</span>
                            {orphanCount > 0 && <span className="depgraph-stat depgraph-stat-warn">⚠️ {orphanCount} orphans</span>}
                        </div>
                    </>
                )}
            </div>

            <div className="depgraph-content">
                {nodes.length > 0 ? (
                    <div className="depgraph-canvas-wrap">
                        <svg
                            ref={svgRef}
                            className="depgraph-svg"
                            viewBox={`0 0 ${dims.w} ${dims.h}`}
                            onWheel={handleWheel}
                            onMouseDown={handleMouseDown}
                            onMouseMove={handleMouseMove}
                            onMouseUp={handleMouseUp}
                            onMouseLeave={handleMouseUp}
                        >
                            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                                {/* Edges */}
                                {edges.map((e, i) => {
                                    const a = nodes.find(n => n.id === e.source);
                                    const b = nodes.find(n => n.id === e.target);
                                    if (!a || !b) return null;
                                    const isHighlighted = hovered && transitiveDeps.has(e.source) && transitiveDeps.has(e.target);
                                    const dimmed = search && (!filteredIds.has(e.source) || !filteredIds.has(e.target));
                                    return (
                                        <line
                                            key={i}
                                            x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                                            className={`depgraph-edge ${isHighlighted ? "depgraph-edge-hl" : ""} ${dimmed ? "depgraph-edge-dim" : ""}`}
                                        />
                                    );
                                })}

                                {/* Nodes */}
                                {nodes.map(n => {
                                    const color = TYPE_COLORS[n.type] || DEFAULT_COLOR;
                                    const isActive = hovered === n.id || (hovered && transitiveDeps.has(n.id));
                                    const dimmed = search && !filteredIds.has(n.id);
                                    const isSelected = selected?.id === n.id;
                                    return (
                                        <g
                                            key={n.id}
                                            className={`depgraph-node ${dimmed ? "depgraph-node-dim" : ""}`}
                                            onMouseEnter={() => setHovered(n.id)}
                                            onMouseLeave={() => setHovered(null)}
                                            onClick={() => setSelected(n)}
                                        >
                                            {/* Orphan ring */}
                                            {n.isOrphan && (
                                                <circle cx={n.x} cy={n.y} r={9} fill="none" stroke="#f59e0b" strokeWidth={1.5} strokeDasharray="3 2" />
                                            )}
                                            <circle
                                                cx={n.x} cy={n.y}
                                                r={isActive ? 7 : 5}
                                                fill={color}
                                                stroke={isSelected ? "#fff" : "none"}
                                                strokeWidth={isSelected ? 2 : 0}
                                                opacity={dimmed ? 0.15 : 1}
                                            />
                                            {(zoom > 0.6 || isActive) && (
                                                <text x={n.x} y={n.y + 14} textAnchor="middle"
                                                    className={`depgraph-label ${isActive ? "depgraph-label-hl" : ""}`}
                                                    opacity={dimmed ? 0.15 : 1}
                                                >
                                                    {n.label}
                                                </text>
                                            )}
                                        </g>
                                    );
                                })}
                            </g>
                        </svg>

                        {/* Legend */}
                        <div className="depgraph-legend">
                            {Object.entries(TYPE_COLORS).slice(0, 6).map(([type, color]) => (
                                <div key={type} className="depgraph-legend-item">
                                    <span className="depgraph-legend-dot" style={{ background: color }} />
                                    <span>{type}</span>
                                </div>
                            ))}
                            <div className="depgraph-legend-item">
                                <span className="depgraph-legend-dot" style={{ border: "2px dashed #f59e0b", background: "transparent" }} />
                                <span>orphan</span>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="pipe-empty">
                        <span className="pipe-empty-icon">🕸️</span>
                        <h3>Dependency Graph</h3>
                        <p>Open a CycloneDX BOM with <code>dependencies[]</code> to visualize the component dependency tree</p>
                        <p style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: 8 }}>
                            Shift+drag to pan, scroll to zoom, click node for details
                        </p>
                    </div>
                )}

                {/* Detail panel */}
                {selected && (
                    <div className="depgraph-detail fade-in">
                        <div className="depgraph-detail-header">
                            <span className={`merge-node-type merge-type-${selected.type}`}>{selected.type}</span>
                            <h3>{selected.fullName}</h3>
                            <button className="merge-file-rm" onClick={() => setSelected(null)}>✕</button>
                        </div>
                        <div className="depgraph-detail-row"><b>Version:</b> {selected.version || "—"}</div>
                        {selected.purl && <div className="depgraph-detail-row"><b>PURL:</b> <code>{selected.purl}</code></div>}
                        {selected.licenses.length > 0 && (
                            <div className="depgraph-detail-row"><b>Licenses:</b> {selected.licenses.join(", ")}</div>
                        )}
                        {selected.isOrphan && (
                            <div className="depgraph-detail-row depgraph-detail-warn">⚠️ Orphan — not referenced in dependency graph</div>
                        )}
                        {selected.hashes.length > 0 && (
                            <div className="depgraph-detail-hashes">
                                <b>Hashes:</b>
                                {selected.hashes.map((h, i) => (
                                    <div key={i} className="depgraph-hash">{h.alg}: <code>{h.content?.slice(0, 16)}...</code></div>
                                ))}
                            </div>
                        )}
                        <div className="depgraph-detail-row">
                            <b>Direct deps:</b> {edges.filter(e => e.source === selected.id).length} |
                            <b> Depended by:</b> {edges.filter(e => e.target === selected.id).length}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
