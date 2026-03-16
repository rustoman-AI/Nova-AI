import { useState, useCallback, useMemo, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
    ReactFlow, Background, Controls, MiniMap, Panel,
    useNodesState, useEdgesState, MarkerType,
    type Node, type Edge, type NodeProps,
    Handle, Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { DatalogQueryPanel } from "./DatalogQueryPanel";
import { QueryLabPanel } from "./QueryLabPanel";

interface AstSummary { total_files: number; total_lines: number; languages: Record<string, number>; build_systems: string[]; declared_deps: number; internal_imports: number; external_imports: number; entry_points: string[]; top_importers: [string, number][]; }
interface BuildSummary { targets: number; resolved_deps: number; build_steps: number; outputs: number; build_commands: string[]; }
interface ChainStats { total_chain_nodes: number; total_chain_edges: number; graphs_connected: number; source_to_trust_depth: number; }
interface SupplyChain { ast: AstSummary; build: BuildSummary; chain_nodes: unknown[]; chain_edges: unknown[]; chain_stats: ChainStats; }

interface SourceNodeData { path: string; language: string; size_bytes: number; lines: number; imports: number; exports: number; is_entry: boolean; }
interface ImportEdge { from_file: string; to_module: string; import_type: string; }
interface DeclaredDep { name: string; version: string; dep_type: string; source: string; }
interface BuildFileI { path: string; build_system: string; declared_deps: DeclaredDep[]; }
interface CodeGraphResult { source_nodes: SourceNodeData[]; import_edges: ImportEdge[]; build_files: BuildFileI[]; stats: AstSummary; }

// ── MetaGraph types ──
interface MetaNode { id: string; kind: string; label: string; properties: Record<string, string>; }
interface MetaEdge { source: string; target: string; kind: string; label: string; weight: number; }
interface MetaGraphStats { total_nodes: number; total_edges: number; file_nodes: number; module_nodes: number; component_nodes: number; vuln_nodes: number; import_edges: number; depends_edges: number; uses_component_edges: number; has_vuln_edges: number; ast_to_sbom_bridges: number; }
interface MetaGraphView { nodes: MetaNode[]; edges: MetaEdge[]; stats: MetaGraphStats; }
interface CveImpactResult { cve_id: string; severity: string; score: number; affected_components: MetaNode[]; affected_files: MetaNode[]; entry_points: MetaNode[]; blast_radius: number; }
interface SupplyChainTrace { package_name: string; importing_files: MetaNode[]; sbom_component: MetaNode | null; transitive_deps: MetaNode[]; vulnerabilities: MetaNode[]; }
interface AttackSurface { vuln_component_count: number; exposed_entry_count: number; exposed_entries: MetaNode[]; risk_paths: { from_vuln_component: string; nodes: string[] }[]; }

// ── TrustGraph types ──
interface TrustNode2 { id: string; name: string; node_type: string; trust_score: number; risk_level: string; details: Record<string, string>; }
interface TrustEdge2 { from: string; to: string; edge_type: string; weight: number; }
interface AttackPath { path: string[]; vulnerability_id: string; severity: string; depth: number; risk_score: number; description: string; }
interface RiskSummary { total_nodes: number; total_edges: number; attack_paths: number; critical_paths: number; avg_trust: number; min_trust: number; max_depth: number; exposed_components: number; supply_chain_risk: string; copyleft_risk: number; untrusted_suppliers: number; }
interface TrustGraphData { nodes: TrustNode2[]; edges: TrustEdge2[]; attack_paths: AttackPath[]; risk_summary: RiskSummary; }

// ── Execution types ──
interface ExecNodeDef { id: string; kind: string; label: string; description: string; status: string; duration_us: number; output_summary: string; }
interface ExecEdgeDef { from: string; to: string; }
interface PipelineResult { graph: { nodes: ExecNodeDef[]; edges: ExecEdgeDef[] }; violations: unknown[]; report: string[]; total_duration_us: number; verdict: string; }

type GraphLayer = 'ast' | 'sbom' | 'build' | 'exec' | 'trust' | 'all';
type SubTab = "overview" | "multigraph" | "imports" | "deps" | "build" | "security";

// ── Path tracing result ──
interface PathNodeI { id: string; label: string; kind: string; layer: string; }
interface GraphPathResult { found: boolean; from: string; to: string; path: PathNodeI[]; edge_types: string[]; depth: number; query_duration_us: number; }

const LANG_META: Record<string, { color: string; icon: string; gradient: string }> = {
    rust: { color: "#dea584", icon: "🦀", gradient: "linear-gradient(135deg, #dea58422, #dea58408)" },
    typescript: { color: "#3178c6", icon: "📘", gradient: "linear-gradient(135deg, #3178c622, #3178c608)" },
    javascript: { color: "#f1e05a", icon: "📒", gradient: "linear-gradient(135deg, #f1e05a22, #f1e05a08)" },
    java: { color: "#b07219", icon: "☕", gradient: "linear-gradient(135deg, #b0721922, #b0721908)" },
    go: { color: "#00ADD8", icon: "🐹", gradient: "linear-gradient(135deg, #00ADD822, #00ADD808)" },
    python: { color: "#3572A5", icon: "🐍", gradient: "linear-gradient(135deg, #3572A522, #3572A508)" },
    c: { color: "#555555", icon: "⚙️", gradient: "linear-gradient(135deg, #55555522, #55555508)" },
    cpp: { color: "#f34b7d", icon: "🔧", gradient: "linear-gradient(135deg, #f34b7d22, #f34b7d08)" },
    kotlin: { color: "#A97BFF", icon: "🟣", gradient: "linear-gradient(135deg, #A97BFF22, #A97BFF08)" },
    ruby: { color: "#701516", icon: "💎", gradient: "linear-gradient(135deg, #70151622, #70151608)" },
    csharp: { color: "#178600", icon: "🟢", gradient: "linear-gradient(135deg, #17860022, #17860008)" },
};

// ━━━━━━━━━━━━ CUSTOM NODE: Source File (EA-style) ━━━━━━━━━━━━
interface EaNodeData { label: string; language: string; lines: number; imports: number; isEntry: boolean; dir: string; sizeBytes: number;[key: string]: unknown; }

function EaSourceNode({ data }: NodeProps<Node<EaNodeData>>) {
    const meta = LANG_META[data.language] || { color: "#666", icon: "📄", gradient: "linear-gradient(135deg, #66666622, #66666608)" };
    const isEntry = data.isEntry;
    return (
        <div className="ea-node" style={{
            borderColor: isEntry ? "#fff" : meta.color,
            background: meta.gradient,
            boxShadow: isEntry ? `0 0 16px ${meta.color}44, 0 4px 12px #00000066` : `0 2px 8px #00000044`,
        }}>
            <Handle type="target" position={Position.Top} className="ea-handle" />
            {/* Header */}
            <div className="ea-header" style={{ borderBottomColor: `${meta.color}33` }}>
                <span className="ea-icon">{meta.icon}</span>
                <span className="ea-title">{data.label}</span>
                {isEntry && <span className="ea-entry-badge">ENTRY</span>}
            </div>
            {/* Attributes (EA stereotype) */}
            <div className="ea-body">
                <div className="ea-attr"><span className="ea-attr-icon">📏</span><span>{data.lines.toLocaleString()} lines</span></div>
                <div className="ea-attr"><span className="ea-attr-icon">🔗</span><span>{data.imports} imports</span></div>
                <div className="ea-attr"><span className="ea-attr-icon">💾</span><span>{(data.sizeBytes / 1024).toFixed(1)} KB</span></div>
            </div>
            {/* Footer: language tag */}
            <div className="ea-footer" style={{ background: `${meta.color}15`, borderTopColor: `${meta.color}22` }}>
                <span style={{ color: meta.color, fontWeight: 700 }}>{data.language}</span>
            </div>
            <Handle type="source" position={Position.Bottom} className="ea-handle" />
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: External Module (EA package) ━━━━━━━━━━━━
interface ExtNodeData { label: string; count: number;[key: string]: unknown; }

function EaExternalNode({ data }: NodeProps<Node<ExtNodeData>>) {
    return (
        <div className="ea-ext-node">
            <Handle type="source" position={Position.Right} className="ea-handle" />
            <div className="ea-ext-header">
                <span>📦</span>
                <span className="ea-ext-name">{data.label}</span>
            </div>
            <div className="ea-ext-count">{data.count} imports</div>
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: Directory Group (EA package) ━━━━━━━━━━━━
interface DirNodeData { label: string; fileCount: number;[key: string]: unknown; }

function EaDirNode({ data }: NodeProps<Node<DirNodeData>>) {
    return (
        <div className="ea-dir-node">
            <div className="ea-dir-header">
                <span>📁</span> <span>{data.label}</span>
                <span className="ea-dir-count">{data.fileCount}</span>
            </div>
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: Build Step (orange) ━━━━━━━━━━━━
interface BuildStepData { label: string; command?: string; status?: string;[key: string]: unknown; }
function BuildStepNode({ data }: NodeProps<Node<BuildStepData>>) {
    return (
        <div style={{ background: '#fa8c160a', border: '2px solid #fa8c16', borderRadius: 10, padding: '8px 12px', minWidth: 140 }}>
            <Handle type="target" position={Position.Top} className="ea-handle" />
            <div style={{ fontSize: 11, fontWeight: 700, color: '#ffc069' }}>🔨 {data.label}</div>
            {data.command && <div style={{ fontSize: 9, color: '#666', marginTop: 2 }}><code>{data.command}</code></div>}
            {data.status && <div style={{ fontSize: 8, color: data.status === 'success' ? '#52c41a' : '#ff4d4f', marginTop: 2 }}>{data.status}</div>}
            <Handle type="source" position={Position.Bottom} className="ea-handle" />
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: Exec Step (blue) ━━━━━━━━━━━━
interface ExecStepNodeData { label: string; description?: string; status?: string; duration?: string; output?: string;[key: string]: unknown; }
function ExecStepNodeComp({ data }: NodeProps<Node<ExecStepNodeData>>) {
    const sc = data.status === 'success' ? '#52c41a' : data.status === 'failed' ? '#ff4d4f' : '#1890ff';
    return (
        <div style={{ background: `${sc}0a`, border: `2px solid ${sc}`, borderRadius: 10, padding: '8px 12px', minWidth: 160 }}>
            <Handle type="target" position={Position.Top} className="ea-handle" />
            <div style={{ fontSize: 11, fontWeight: 700, color: sc }}>{data.label}</div>
            {data.description && <div style={{ fontSize: 9, color: '#888', marginTop: 2 }}>{data.description}</div>}
            {data.duration && <div style={{ fontSize: 8, color: '#666', marginTop: 2 }}>⏱ {data.duration}</div>}
            {data.output && <div style={{ fontSize: 8, color: '#aaa', marginTop: 2, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.output}</div>}
            <Handle type="source" position={Position.Bottom} className="ea-handle" />
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: Trust (purple/red by risk) ━━━━━━━━━━━━
interface TrustNodeData { label: string; nodeType?: string; trustScore?: number; riskLevel?: string;[key: string]: unknown; }
function TrustNodeComp({ data }: NodeProps<Node<TrustNodeData>>) {
    const rc: Record<string, string> = { critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', none: '#722ed1' };
    const c = rc[data.riskLevel || 'none'] || '#722ed1';
    const icon: Record<string, string> = { component: '🧩', vulnerability: '⚠️', license: '📜', supplier: '🏢' };
    return (
        <div style={{ background: `${c}0a`, border: `2px solid ${c}`, borderRadius: 10, padding: '8px 12px', minWidth: 120 }}>
            <Handle type="target" position={Position.Top} className="ea-handle" />
            <div style={{ fontSize: 11, fontWeight: 700, color: c }}>{icon[data.nodeType || ''] || '🔷'} {data.label}</div>
            {data.trustScore !== undefined && <div style={{ fontSize: 9, color: '#888', marginTop: 2 }}>Trust: {Math.round(data.trustScore * 100)}%</div>}
            <Handle type="source" position={Position.Bottom} className="ea-handle" />
        </div>
    );
}

const nodeTypes = { eaSource: EaSourceNode, eaExternal: EaExternalNode, eaDir: EaDirNode, metaComp: MetaComponentNode, metaVuln: MetaVulnNode, metaMod: MetaModuleNode, buildStep: BuildStepNode, execStep: ExecStepNodeComp, trustNode: TrustNodeComp };

// ━━━━━━━━━━━━ CUSTOM NODE: SBOM Component (purple) ━━━━━━━━━━━━
interface MetaCompData { label: string; version?: string; license?: string; purl?: string;[key: string]: unknown; }

function MetaComponentNode({ data }: NodeProps<Node<MetaCompData>>) {
    return (
        <div className="meta-comp-node">
            <Handle type="target" position={Position.Top} className="ea-handle" />
            <div className="meta-comp-title">🧩 {data.label}</div>
            {data.version && <div className="meta-comp-detail">v{data.version}</div>}
            {data.license && <div className="meta-comp-detail">📜 {data.license}</div>}
            <Handle type="source" position={Position.Bottom} className="ea-handle" />
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: Vulnerability (red) ━━━━━━━━━━━━
interface MetaVulnData { label: string; severity?: string; score?: string;[key: string]: unknown; }

function MetaVulnNode({ data }: NodeProps<Node<MetaVulnData>>) {
    const sevColor = data.severity === 'CRITICAL' ? '#ff4d4f' : data.severity === 'HIGH' ? '#fa8c16' : '#faad14';
    return (
        <div className="meta-vuln-node">
            <Handle type="target" position={Position.Top} className="ea-handle" />
            <div className="meta-vuln-title">⚠️ {data.label}</div>
            <div className="meta-vuln-detail" style={{ color: sevColor }}>{data.severity || 'UNKNOWN'} {data.score ? `(${data.score})` : ''}</div>
            <Handle type="source" position={Position.Bottom} className="ea-handle" />
        </div>
    );
}

// ━━━━━━━━━━━━ CUSTOM NODE: Module (blue dashed) ━━━━━━━━━━━━
interface MetaModData { label: string; version?: string;[key: string]: unknown; }

function MetaModuleNode({ data }: NodeProps<Node<MetaModData>>) {
    return (
        <div className="meta-mod-node">
            <Handle type="target" position={Position.Left} className="ea-handle" />
            <div className="meta-mod-title">📦 {data.label}</div>
            {data.version && <div className="meta-mod-detail">v{data.version}</div>}
            <Handle type="source" position={Position.Right} className="ea-handle" />
        </div>
    );
}

// ━━━━━━━━━━━━ LAYOUT: MetaGraph multi-layer ━━━━━━━━━━━━
function buildMetaFlowGraph(mg: MetaGraphView): { flowNodes: Node[]; flowEdges: Edge[] } {
    const flowNodes: Node[] = [];
    const flowEdges: Edge[] = [];

    // Layer positions (horizontal lanes)
    const LAYER_Y: Record<string, number> = { File: 0, Module: 200, Component: 400, Vulnerability: 600 };
    const COL_W = 180;

    // Group nodes by kind, count per layer
    const byKind: Record<string, MetaNode[]> = {};
    mg.nodes.forEach(n => { (byKind[n.kind] = byKind[n.kind] || []).push(n); });

    // Place nodes in horizontal rows by kind
    for (const [kind, nodes] of Object.entries(byKind)) {
        const y = LAYER_Y[kind] ?? 800;
        const nodeType = kind === 'Component' ? 'metaComp' : kind === 'Vulnerability' ? 'metaVuln' : kind === 'Module' ? 'metaMod' : 'eaSource';

        nodes.forEach((n, i) => {
            // More aggressive wrapping for SBOM nodes
            const cols = Math.max(8, Math.ceil(Math.sqrt(nodes.length * 2)));
            const col = i % cols;
            const row = Math.floor(i / cols);
            flowNodes.push({
                id: n.id,
                type: nodeType,
                position: { x: col * COL_W, y: y + row * 80 },
                data: {
                    label: n.label,
                    language: n.properties.language || '',
                    lines: parseInt(n.properties.lines || '0'),
                    imports: parseInt(n.properties.imports || '0'),
                    isEntry: n.properties.is_entry === 'true',
                    dir: '',
                    sizeBytes: parseInt(n.properties.size_bytes || '0'),
                    version: n.properties.version,
                    license: n.properties.license,
                    purl: n.properties.purl,
                    severity: n.properties.severity,
                    score: n.properties.score,
                    count: 0,
                    fileCount: 0,
                },
            });
        });
    }

    // Edges with colors by kind
    const EDGE_COLORS: Record<string, string> = {
        Imports: '#52c41a', DependsOn: '#722ed1', UsesComponent: '#faad14', HasVuln: '#ff4d4f', Builds: '#1890ff', Contains: '#13c2c2',
    };
    let eId = 0;
    const edgeSeen = new Set<string>();
    mg.edges.forEach(e => {
        const key = `${e.source}→${e.target}`;
        if (edgeSeen.has(key)) return;
        edgeSeen.add(key);
        const color = EDGE_COLORS[e.kind] || '#666';
        flowEdges.push({
            id: `me-${eId++}`, source: e.source, target: e.target,
            type: 'smoothstep',
            style: { stroke: color, strokeWidth: e.kind === 'HasVuln' ? 2.5 : 1.5, strokeDasharray: e.kind === 'UsesComponent' ? '6,3' : undefined },
            markerEnd: { type: MarkerType.ArrowClosed, color, width: 10, height: 10 },
            animated: e.kind === 'HasVuln' || e.kind === 'UsesComponent',
            label: e.label,
            labelStyle: { fill: color, fontSize: 7, fontWeight: 600 },
            labelBgStyle: { fill: '#0e0e1a', fillOpacity: 0.9 },
            labelBgPadding: [3, 1] as [number, number],
        });
    });

    return { flowNodes, flowEdges };
}

// ━━━━━━━━━━━━ LAYOUT: Hierarchical by directory ━━━━━━━━━━━━
function buildEAGraph(sources: SourceNodeData[], edges: ImportEdge[]): { flowNodes: Node[]; flowEdges: Edge[] } {
    const NODE_W = 200;
    const NODE_H = 120;
    const DIR_GAP = 60;
    const COL_GAP = 30;
    const TOP_MARGIN = 20;

    // Group by directory
    const dirGroups: Record<string, SourceNodeData[]> = {};
    sources.forEach(n => {
        const parts = n.path.split("/");
        const dir = parts.length > 1 ? parts.slice(0, -1).join("/") : ".";
        (dirGroups[dir] = dirGroups[dir] || []).push(n);
    });

    // Sort dirs: entries first, then by file count desc
    const dirs = Object.keys(dirGroups).sort((a, b) => {
        const aHasEntry = dirGroups[a].some(n => n.is_entry);
        const bHasEntry = dirGroups[b].some(n => n.is_entry);
        if (aHasEntry !== bHasEntry) return aHasEntry ? -1 : 1;
        return dirGroups[b].length - dirGroups[a].length;
    });

    const flowNodes: Node[] = [];
    const flowEdges: Edge[] = [];
    let xOffset = 280;
    let yOffset = TOP_MARGIN;
    let rowMaxHeight = 0;
    const MAX_WIDTH = 6000; // Target width for AST layer to wrap 

    // Place file nodes grouped by directory (flex wrap)
    for (const dir of dirs) {
        const group = dirGroups[dir];
        group.sort((a, b) => {
            if (a.is_entry !== b.is_entry) return a.is_entry ? -1 : 1;
            return b.imports - a.imports;
        });

        // Use more columns for large directories
        const cols = Math.min(Math.max(Math.ceil(Math.sqrt(group.length)), 3), 12);
        const groupWidth = cols * (NODE_W + COL_GAP);
        const groupHeight = Math.ceil(group.length / cols) * (NODE_H + 16) + 36 + DIR_GAP;

        if (xOffset + groupWidth > MAX_WIDTH && xOffset > 280) {
            xOffset = 280;
            yOffset += rowMaxHeight;
            rowMaxHeight = 0;
        }

        // Dir label node
        flowNodes.push({
            id: `dir:${dir}`, type: "eaDir", position: { x: xOffset, y: yOffset },
            data: { label: dir, fileCount: group.length }, draggable: false, selectable: false,
        });

        group.forEach((n, i) => {
            const col = i % cols;
            const row = Math.floor(i / cols);
            flowNodes.push({
                id: n.path, type: "eaSource",
                position: { x: xOffset + col * (NODE_W + COL_GAP), y: yOffset + 36 + row * (NODE_H + 16) },
                data: { label: n.path.split("/").pop() || n.path, language: n.language, lines: n.lines, imports: n.imports, isEntry: n.is_entry, dir, sizeBytes: n.size_bytes },
            });
        });

        xOffset += groupWidth + DIR_GAP;
        rowMaxHeight = Math.max(rowMaxHeight, groupHeight);
    }

    // Pre-build lookup maps for O(1) resolution
    const fileSet = new Set(sources.map(n => n.path));
    const pathIndex = new Map<string, string>(); // modPath → file path
    sources.forEach(n => {
        // Index by path segments for fast module resolution
        const stripped = n.path.replace(/\.[^.]+$/, "");
        const parts = stripped.split("/");
        for (let k = 1; k <= parts.length; k++) {
            const suffix = parts.slice(-k).join("/");
            if (!pathIndex.has(suffix)) pathIndex.set(suffix, n.path);
        }
    });

    // Build edges — internal file-to-file (O(1) lookup per edge)
    const seen = new Set<string>();
    let eId = 0;

    edges.forEach(e => {
        if (e.import_type === "internal" && fileSet.has(e.from_file)) {
            const modPath = e.to_module.replace(/::/g, "/").replace(/\./g, "/");
            const target = pathIndex.get(modPath);
            if (target && target !== e.from_file) {
                const key = `${e.from_file}→${target}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    flowEdges.push({
                        id: `e-${eId++}`, source: e.from_file, target: target,
                        type: "smoothstep",
                        style: { stroke: "#52c41a", strokeWidth: 2 },
                        markerEnd: { type: MarkerType.ArrowClosed, color: "#52c41a", width: 12, height: 12 },
                        label: "uses",
                        labelStyle: { fill: "#52c41a", fontSize: 8, fontWeight: 600 },
                        labelBgStyle: { fill: "#0e0e1a", fillOpacity: 0.9 },
                        labelBgPadding: [4, 2] as [number, number],
                    });
                }
            }
        }
    });

    // External modules — left column (Set-based dedup)
    const extModules: Record<string, { count: number; importers: Set<string> }> = {};
    edges.forEach(e => {
        if (e.import_type === "external") {
            const mod = e.to_module.split("::")[0].split("/")[0];
            if (!extModules[mod]) extModules[mod] = { count: 0, importers: new Set() };
            extModules[mod].count++;
            extModules[mod].importers.add(e.from_file);
        }
    });

    const extList = Object.entries(extModules).sort((a, b) => b[1].count - a[1].count).slice(0, 25);
    extList.forEach(([mod, info], i) => {
        const id = `ext:${mod}`;
        flowNodes.push({
            id,
            type: "eaExternal",
            position: { x: 0, y: TOP_MARGIN + i * 52 },
            data: { label: mod, count: info.count },
        });

        // Connect to first 2 importers
        const importerArr = [...info.importers];
        importerArr.slice(0, 2).forEach((imp) => {
            if (fileSet.has(imp)) {
                flowEdges.push({
                    id: `ext-e-${eId++}`,
                    source: id, target: imp,
                    type: "smoothstep",
                    style: { stroke: "#1890ff44", strokeWidth: 1, strokeDasharray: "6,3" },
                    markerEnd: { type: MarkerType.ArrowClosed, color: "#1890ff44", width: 8, height: 8 },
                });
            }
        });
    });

    return { flowNodes, flowEdges };
}

export default function RustSourcePanel() {
    const [rootDir, setRootDir] = useState("");
    const [result, setResult] = useState<SupplyChain | null>(null);
    const [codeGraph, setCodeGraph] = useState<CodeGraphResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [parseTimeMs, setParseTimeMs] = useState<number | null>(null);
    const [subTab, setSubTab] = useState<SubTab>("overview");
    const [filterImport, setFilterImport] = useState("all");
    const [glowingPaths, setGlowingPaths] = useState<string[][]>([]); // Added state

    // ── GraphState Engine: unified canvas ──
    const [gNodes, setGNodes, onGNodesChange] = useNodesState<Node>([]);
    const [gEdges, setGEdges, onGEdgesChange] = useEdgesState<Edge>([]);
    const [activeLayer, setActiveLayer] = useState<GraphLayer>('ast');
    const [graphQuery, setGraphQuery] = useState("");
    const layerCache = useRef<Record<string, { nodes: Node[]; edges: Edge[] }>>({});

    // MetaGraph + security query state
    const [metaGraph, setMetaGraph] = useState<MetaGraphView | null>(null);
    const [sbomPath, setSbomPath] = useState("");
    const [cveId, setCveId] = useState("");
    const [pkgName, setPkgName] = useState("");
    const [cveResult, setCveResult] = useState<CveImpactResult | null>(null);
    const [traceResult, setTraceResult] = useState<SupplyChainTrace | null>(null);
    const [attackResult, setAttackResult] = useState<AttackSurface | null>(null);
    // Trust + Exec data
    const [trustData, setTrustData] = useState<TrustGraphData | null>(null);
    // Overlay modes
    const [cveOverlay, setCveOverlay] = useState(false);
    const [heatmapMode, setHeatmapMode] = useState(false);
    const [execData, setExecData] = useState<PipelineResult | null>(null);
    // Path tracing
    const [pathResult, setPathResult] = useState<GraphPathResult | null>(null);
    const [pathHighlight, setPathHighlight] = useState<Set<string>>(new Set());

    // ── Layer builder helpers ──
    const buildTrustFlowGraph = useCallback((tg: TrustGraphData): { nodes: Node[]; edges: Edge[] } => {
        const nodes: Node[] = [];
        const edges: Edge[] = [];
        const typeY: Record<string, number> = { component: 0, vulnerability: 250, license: 500, supplier: 750 };
        const byType: Record<string, TrustNode2[]> = {};
        tg.nodes.forEach(n => { (byType[n.node_type] = byType[n.node_type] || []).push(n); });
        for (const [typ, list] of Object.entries(byType)) {
            const y = typeY[typ] ?? 1000;
            list.forEach((n, i) => {
                const cols = Math.min(8, list.length);
                nodes.push({
                    id: n.id, type: 'trustNode', position: { x: (i % cols) * 170, y: y + Math.floor(i / cols) * 80 },
                    data: { label: n.name, nodeType: n.node_type, trustScore: n.trust_score, riskLevel: n.risk_level, layer: 'trust' }
                });
            });
        }
        const edgeColors: Record<string, string> = { depends_on: '#722ed1', has_vuln: '#ff4d4f', licensed_by: '#13c2c2', supplied_by: '#1890ff', propagates_to: '#fa8c16' };
        tg.edges.forEach((e, i) => {
            edges.push({
                id: `te-${i}`, source: e.from, target: e.to, type: 'smoothstep',
                style: { stroke: edgeColors[e.edge_type] || '#666', strokeWidth: e.edge_type === 'has_vuln' ? 2.5 : 1.5 },
                markerEnd: { type: MarkerType.ArrowClosed, color: edgeColors[e.edge_type] || '#666', width: 10, height: 10 }
            });
        });
        return { nodes, edges };
    }, []);

    const buildExecFlowGraph = useCallback((pr: PipelineResult): { nodes: Node[]; edges: Edge[] } => {
        const nodes: Node[] = pr.graph.nodes.map((n, i) => ({
            id: n.id, type: 'execStep', position: { x: 300, y: i * 130 },
            data: { label: n.label, description: n.description, status: n.status, duration: n.duration_us > 0 ? `${n.duration_us}µs` : '', output: n.output_summary, layer: 'exec' },
        }));
        const edges: Edge[] = pr.graph.edges.map((e, i) => ({
            id: `ee-${i}`, source: e.from, target: e.to, type: 'smoothstep',
            style: { stroke: '#1890ff', strokeWidth: 2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#1890ff', width: 10, height: 10 },
        }));
        return { nodes, edges };
    }, []);

    const buildBuildFlowGraph = useCallback((): { nodes: Node[]; edges: Edge[] } => {
        if (!result) return { nodes: [], edges: [] };
        const nodes: Node[] = [];
        const edges: Edge[] = [];
        result.chain_nodes.forEach((cn: any, i: number) => {
            nodes.push({
                id: cn.id || `cn-${i}`, type: 'buildStep', position: { x: (i % 4) * 200, y: Math.floor(i / 4) * 120 },
                data: { label: cn.label || cn.id || `Step ${i}`, command: cn.command || '', layer: 'build' }
            });
        });
        result.chain_edges.forEach((ce: any, i: number) => {
            edges.push({
                id: `be-${i}`, source: ce.from || ce.source, target: ce.to || ce.target, type: 'smoothstep',
                style: { stroke: '#fa8c16', strokeWidth: 2 },
                markerEnd: { type: MarkerType.ArrowClosed, color: '#fa8c16', width: 10, height: 10 }
            });
        });
        return { nodes, edges };
    }, [result]);

    // ── Switch active layer ──
    const switchLayer = useCallback((layer: GraphLayer) => {
        setActiveLayer(layer);
        if (layer === 'all') {
            const allN: Node[] = []; const allE: Edge[] = [];
            let currentY = 0;
            // Ordered canonical layer bands
            const order: GraphLayer[] = ['exec', 'ast', 'build', 'sbom', 'trust'];
            for (const lk of order) {
                const data = layerCache.current[lk];
                if (!data || data.nodes.length === 0) continue;

                let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
                data.nodes.forEach(n => {
                    if (n.position.x < minX) minX = n.position.x;
                    if (n.position.x > maxX) maxX = n.position.x;
                    if (n.position.y < minY) minY = n.position.y;
                    if (n.position.y > maxY) maxY = n.position.y;
                });

                const centerX = (minX + maxX) / 2;
                const topOffset = currentY - minY;

                data.nodes.forEach(n => {
                    allN.push({ ...n, position: { x: n.position.x - centerX, y: n.position.y + topOffset } });
                });
                allE.push(...data.edges);

                currentY += (maxY - minY) + 400; // 400px band gap between layers
            }

            // Cross-layer bridge edges
            const bridgeEdges: Edge[] = [];
            let bId = 0;
            const nodeIds = new Set(allN.map(n => n.id));
            const astNodes = layerCache.current['ast']?.nodes || [];
            const sbomNodes = layerCache.current['sbom']?.nodes || [];
            if (astNodes.length > 0 && sbomNodes.length > 0) {
                const entry = astNodes.find(n => (n.data as any)?.isEntry) || astNodes[0];
                if (entry && sbomNodes[0]) {
                    bridgeEdges.push({
                        id: `bridge-${bId++}`, source: entry.id, target: sbomNodes[0].id, type: 'smoothstep',
                        style: { stroke: '#52c41a', strokeWidth: 2, strokeDasharray: '8,4' }, label: 'AST→SBOM',
                        labelStyle: { fill: '#52c41a', fontSize: 8, fontWeight: 600 }, labelBgStyle: { fill: '#0e0e1a', fillOpacity: 0.9 }, labelBgPadding: [3, 1] as [number, number],
                        markerEnd: { type: MarkerType.ArrowClosed, color: '#52c41a', width: 10, height: 10 }
                    });
                }
            }
            const buildNodes = layerCache.current['build']?.nodes || [];
            if (buildNodes.length > 0 && astNodes.length > 0) {
                bridgeEdges.push({
                    id: `bridge-${bId++}`, source: astNodes[0].id, target: buildNodes[0].id, type: 'smoothstep',
                    style: { stroke: '#fa8c16', strokeWidth: 2, strokeDasharray: '8,4' }, label: 'AST→Build',
                    labelStyle: { fill: '#fa8c16', fontSize: 8, fontWeight: 600 }, labelBgStyle: { fill: '#0e0e1a', fillOpacity: 0.9 }, labelBgPadding: [3, 1] as [number, number],
                    markerEnd: { type: MarkerType.ArrowClosed, color: '#fa8c16', width: 10, height: 10 }
                });
            }
            const trustNodes = layerCache.current['trust']?.nodes || [];
            if (sbomNodes.length > 0 && trustNodes.length > 0) {
                bridgeEdges.push({
                    id: `bridge-${bId++}`, source: sbomNodes[0].id, target: trustNodes[0].id, type: 'smoothstep',
                    style: { stroke: '#722ed1', strokeWidth: 2, strokeDasharray: '8,4' }, label: 'SBOM→Trust',
                    labelStyle: { fill: '#722ed1', fontSize: 8, fontWeight: 600 }, labelBgStyle: { fill: '#0e0e1a', fillOpacity: 0.9 }, labelBgPadding: [3, 1] as [number, number],
                    markerEnd: { type: MarkerType.ArrowClosed, color: '#722ed1', width: 10, height: 10 }
                });
            }
            const execNodes = layerCache.current['exec']?.nodes || [];
            if (execNodes.length > 0 && buildNodes.length > 0) {
                bridgeEdges.push({
                    id: `bridge-${bId++}`, source: execNodes[execNodes.length - 1].id, target: buildNodes[0].id, type: 'smoothstep',
                    style: { stroke: '#1890ff', strokeWidth: 2, strokeDasharray: '8,4' }, label: 'Exec→Build',
                    labelStyle: { fill: '#1890ff', fontSize: 8, fontWeight: 600 }, labelBgStyle: { fill: '#0e0e1a', fillOpacity: 0.9 }, labelBgPadding: [3, 1] as [number, number],
                    markerEnd: { type: MarkerType.ArrowClosed, color: '#1890ff', width: 10, height: 10 }
                });
            }
            allE.push(...bridgeEdges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target)));
            setGNodes(allN); setGEdges(allE);
        } else {
            const cached = layerCache.current[layer];
            if (cached) { setGNodes(cached.nodes); setGEdges(cached.edges); }
            else { setGNodes([]); setGEdges([]); }
        }
    }, [setGNodes, setGEdges]);

    // ── Scan source code ──
    const scan = useCallback(async () => {
        if (!rootDir.trim()) return;
        setLoading(true);
        const t0 = performance.now();
        try {
            const [summary, graph] = await Promise.all([
                invoke<SupplyChain>("scan_supply_chain", { rootDir, sbomPath: null }),
                invoke<CodeGraphResult>("scan_code_graph", { rootDir }),
            ]);
            setResult(summary);
            setCodeGraph(graph);
            // Cache AST layer
            const { flowNodes, flowEdges } = buildEAGraph(graph.source_nodes, graph.import_edges);
            layerCache.current['ast'] = { nodes: flowNodes, edges: flowEdges };
            // Cache Build layer from chain
            const buildFlow = buildBuildFlowGraph();
            layerCache.current['build'] = buildFlow;
            // Set active
            setGNodes(flowNodes); setGEdges(flowEdges);
            setActiveLayer('ast');
            setParseTimeMs(performance.now() - t0);
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [rootDir, setGNodes, setGEdges, buildBuildFlowGraph]);

    // ── Build MetaGraph (SBOM layer) ──
    const buildMeta = useCallback(async () => {
        if (!rootDir.trim()) return;
        setLoading(true);
        try {
            const mg = await invoke<MetaGraphView>("build_meta_graph", { rootDir, sbomPath: sbomPath || null });
            setMetaGraph(mg);
            const { flowNodes, flowEdges } = buildMetaFlowGraph(mg);
            layerCache.current['sbom'] = { nodes: flowNodes, edges: flowEdges };
            setGNodes(flowNodes); setGEdges(flowEdges);
            setActiveLayer('sbom');
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [rootDir, sbomPath, setGNodes, setGEdges]);

    // ── Build Trust layer ──
    const buildTrust = useCallback(async () => {
        if (!sbomPath.trim()) return;
        setLoading(true);
        try {
            const tg = await invoke<TrustGraphData>("build_trust_graph", { sbomPath });
            setTrustData(tg);
            const flow = buildTrustFlowGraph(tg);
            layerCache.current['trust'] = flow;
            setGNodes(flow.nodes); setGEdges(flow.edges);
            setActiveLayer('trust');
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [sbomPath, buildTrustFlowGraph, setGNodes, setGEdges]);

    // ── Run Execution pipeline ──
    const runExec = useCallback(async () => {
        if (!sbomPath.trim()) return;
        setLoading(true);
        try {
            const pr = await invoke<PipelineResult>("run_devsecops_pipeline", { sbomPath });
            setExecData(pr);
            const flow = buildExecFlowGraph(pr);
            layerCache.current['exec'] = flow;
            setGNodes(flow.nodes); setGEdges(flow.edges);
            setActiveLayer('exec');
        } catch (e) { alert(String(e)); }
        setLoading(false);
    }, [sbomPath, buildExecFlowGraph, setGNodes, setGEdges]);

    // ── Security queries ──
    const queryCve = useCallback(async () => {
        if (!rootDir.trim() || !sbomPath.trim() || !cveId.trim()) return;
        try { setCveResult(await invoke<CveImpactResult>("query_cve_impact", { rootDir, sbomPath, cveId })); } catch (e) { alert(String(e)); }
    }, [rootDir, sbomPath, cveId]);

    const queryTrace = useCallback(async () => {
        if (!rootDir.trim() || !pkgName.trim()) return;
        try { setTraceResult(await invoke<SupplyChainTrace>("query_supply_chain_trace", { rootDir, sbomPath: sbomPath || null, packageName: pkgName })); } catch (e) { alert(String(e)); }
    }, [rootDir, sbomPath, pkgName]);

    const queryAttack = useCallback(async () => {
        if (!rootDir.trim() || !sbomPath.trim()) return;
        try { setAttackResult(await invoke<AttackSurface>("query_attack_surface", { rootDir, sbomPath })); } catch (e) { alert(String(e)); }
    }, [rootDir, sbomPath]);

    // ── Path tracing (from→to syntax) ──
    const tracePath = useCallback(async (from: string, to: string) => {
        if (!rootDir.trim()) return;
        try {
            const pr = await invoke<GraphPathResult>("trace_graph_path", { rootDir, sbomPath: sbomPath || null, fromQuery: from, toQuery: to });
            setPathResult(pr);
            if (pr.found) {
                setPathHighlight(new Set(pr.path.map(n => n.id)));
                // Set glowing paths for edges
                const newGlowingPaths: string[][] = [];
                for (let i = 0; i < pr.path.length - 1; i++) {
                    newGlowingPaths.push([pr.path[i].id, pr.path[i + 1].id]);
                }
                setGlowingPaths(newGlowingPaths);
            } else {
                setPathHighlight(new Set());
                setGlowingPaths([]);
            }
        } catch (e) { alert(String(e)); }
    }, [rootDir, sbomPath]);

    // ── GraphQuery filter ──
    const filteredGNodes = useMemo(() => {
        let nodes = gNodes;
        // GraphQuery text filter
        if (graphQuery.trim()) {
            const q = graphQuery.toLowerCase();
            const matchIds = new Set(nodes.filter(n => {
                const d = n.data as Record<string, unknown>;
                return (String(d.label || '')).toLowerCase().includes(q)
                    || (String(d.language || '')).toLowerCase().includes(q)
                    || (String(d.nodeType || '')).toLowerCase().includes(q)
                    || (String(d.riskLevel || '')).toLowerCase().includes(q)
                    || n.id.toLowerCase().includes(q);
            }).map(n => n.id));
            nodes = nodes.map(n => matchIds.has(n.id) ? n : { ...n, style: { ...n.style, opacity: 0.15 } });
        }
        // CVE overlay — highlight vuln-connected nodes
        if (cveOverlay) {
            nodes = nodes.map(n => {
                const d = n.data as Record<string, unknown>;
                const isVuln = n.type === 'metaVuln' || n.type === 'trustNode' && (d.riskLevel === 'critical' || d.riskLevel === 'high');
                return isVuln ? { ...n, style: { ...n.style, boxShadow: '0 0 16px #ff4d4f', border: '3px solid #ff4d4f' } } : n;
            });
        }
        // Heatmap — opacity by dep_count / max
        if (heatmapMode) {
            const deps = nodes.map(n => Number((n.data as any)?.depCount || (n.data as any)?.imports || 0));
            const maxDep = Math.max(1, ...deps);
            nodes = nodes.map(n => {
                const dc = Number((n.data as any)?.depCount || (n.data as any)?.imports || 0);
                return { ...n, style: { ...n.style, opacity: 0.2 + 0.8 * (dc / maxDep) } };
            });
        }
        // Path highlight
        if (pathHighlight.size > 0) {
            nodes = nodes.map(n => pathHighlight.has(n.id)
                ? { ...n, style: { ...n.style, boxShadow: '0 0 20px #52c41a', border: '3px solid #52c41a', opacity: 1 } }
                : { ...n, style: { ...n.style, opacity: 0.12 } });
        }
        return nodes;
    }, [gNodes, graphQuery, cveOverlay, heatmapMode, pathHighlight]);

    const filteredGEdges = useMemo(() => {
        let edges = gEdges;
        // Apply Glowing Paths (SecQL)
        const pathEdges = new Set<string>();
        for (const path of glowingPaths) {
            pathEdges.add(`${path[0]}->${path[1]}`);
        }

        edges = edges.map(e => {
            if (pathEdges.has(`${e.source}->${e.target}`)) {
                return {
                    ...e,
                    animated: true,
                    className: "animated-glowing-edge",
                    style: { ...e.style, stroke: "#ff3366", strokeWidth: 3, filter: "drop-shadow(0 0 8px #ff3366)" },
                    markerEnd: { type: MarkerType.ArrowClosed, color: "#ff3366" },
                    zIndex: 1000
                };
            }
            return e;
        });
        return edges;
    }, [gEdges, glowingPaths]);

    const r = result;
    const ast = r?.ast;
    const cg = codeGraph;

    const filteredImports = useMemo(() => {
        if (!cg) return [];
        return cg.import_edges.filter(e => filterImport === "all" || e.import_type === filterImport);
    }, [cg, filterImport]);

    // ── Layer definitions (canonical hierarchy: Exec→AST→Build→SBOM→Trust) ──
    const LAYERS: { key: GraphLayer; icon: string; label: string; sub: string; color: string; count: number }[] = [
        { key: 'exec', icon: '⚙️', label: 'Exec', sub: 'CI/CD pipeline', color: '#1890ff', count: layerCache.current['exec']?.nodes.length || 0 },
        { key: 'ast', icon: '🧬', label: 'AST', sub: 'files / functions', color: '#eb2f96', count: layerCache.current['ast']?.nodes.length || 0 },
        { key: 'build', icon: '🔨', label: 'Build', sub: 'targets / artifacts', color: '#fa8c16', count: layerCache.current['build']?.nodes.length || 0 },
        { key: 'sbom', icon: '📦', label: 'SBOM', sub: 'packages / modules', color: '#52c41a', count: layerCache.current['sbom']?.nodes.length || 0 },
        { key: 'trust', icon: '🛡️', label: 'Trust', sub: 'certs / CVE / FSTEC', color: '#722ed1', count: layerCache.current['trust']?.nodes.length || 0 },
        { key: 'all', icon: '🌐', label: 'All', sub: 'merged view', color: '#e0e0e0', count: Object.values(layerCache.current).reduce((s, v) => s + v.nodes.length, 0) },
    ];

    return (
        <div style={{ padding: "24px", maxWidth: 1600, margin: "0 auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <h2 style={{ margin: 0 }}>🦀 Code Intelligence</h2>
                {ast && <span className="rs-badge">{ast.total_files} files · {ast.total_lines.toLocaleString()} lines · {ast.declared_deps} deps</span>}
                {parseTimeMs !== null && <span className="rs-time-badge">⚡ {parseTimeMs < 1000 ? `${parseTimeMs.toFixed(0)}ms` : `${(parseTimeMs / 1000).toFixed(2)}s`}</span>}
            </div>

            <div className="rs-form">
                <input className="rs-inp" style={{ flex: 1 }} value={rootDir} onChange={e => setRootDir(e.target.value)}
                    placeholder="Project root directory" onKeyDown={e => e.key === "Enter" && scan()} />
                <input className="rs-inp" style={{ width: 300 }} value={sbomPath} onChange={e => setSbomPath(e.target.value)} placeholder="SBOM JSON path (optional)" />
                <button onClick={scan} disabled={loading} className="rs-btn">{loading ? "⏳ Scanning..." : "🦀 Parse Source"}</button>
            </div>

            {ast && (
                <>
                    <div className="rs-tabs">
                        {(["overview", "multigraph", "security", "imports", "deps", "build"] as SubTab[]).map(t => (
                            <button key={t} className={`rs-tab ${subTab === t ? "active" : ""}`} onClick={() => setSubTab(t)}>
                                {{ overview: "📊 Overview", multigraph: "🌐 MultiGraph", security: "🛡️ Security", imports: "🔗 Imports", deps: "📦 Dependencies", build: "🔨 Build" }[t]}
                            </button>
                        ))}
                    </div>

                    {/* ─── OVERVIEW ─── */}
                    {subTab === "overview" && (
                        <div className="rs-grid">
                            <div className="rs-card rs-card-wide">
                                <div className="rs-card-title">📊 Project Summary</div>
                                <div className="rs-stats-grid">
                                    <div className="rs-stat"><div className="rs-stat-val">{ast.total_files}</div><div className="rs-stat-label">Source Files</div></div>
                                    <div className="rs-stat"><div className="rs-stat-val">{ast.total_lines.toLocaleString()}</div><div className="rs-stat-label">Lines of Code</div></div>
                                    <div className="rs-stat"><div className="rs-stat-val">{ast.internal_imports + ast.external_imports}</div><div className="rs-stat-label">Total Imports</div></div>
                                    <div className="rs-stat"><div className="rs-stat-val">{ast.declared_deps}</div><div className="rs-stat-label">Dependencies</div></div>
                                    <div className="rs-stat"><div className="rs-stat-val">{ast.entry_points.length}</div><div className="rs-stat-label">Entry Points</div></div>
                                    <div className="rs-stat"><div className="rs-stat-val">{Object.keys(ast.languages).length}</div><div className="rs-stat-label">Languages</div></div>
                                    {parseTimeMs !== null && <div className="rs-stat"><div className="rs-stat-val" style={{ color: parseTimeMs < 1000 ? '#52c41a' : '#fa8c16' }}>{parseTimeMs < 1000 ? `${parseTimeMs.toFixed(0)}ms` : `${(parseTimeMs / 1000).toFixed(2)}s`}</div><div className="rs-stat-label">Parse Time</div></div>}
                                </div>
                            </div>
                            <div className="rs-card">
                                <div className="rs-card-title">🌐 Languages</div>
                                {Object.entries(ast.languages).sort((a, b) => b[1] - a[1]).map(([lang, count]) => {
                                    const m = LANG_META[lang] || { color: "#666", icon: "📄" };
                                    return (
                                        <div key={lang} className="rs-lang-row">
                                            <span>{m.icon}</span>
                                            <span className="rs-lang-name">{lang}</span>
                                            <div className="rs-bar"><div className="rs-bar-fill" style={{ width: `${(count / ast.total_files) * 100}%`, background: m.color }} /></div>
                                            <span className="rs-lang-count">{count} ({Math.round(count / ast.total_files * 100)}%)</span>
                                        </div>
                                    );
                                })}
                            </div>
                            <div className="rs-card">
                                <div className="rs-card-title">🔗 Import Analysis</div>
                                <div style={{ padding: "4px 0" }}>
                                    <div className="rs-import-bar">
                                        <div style={{ width: `${ast.internal_imports / Math.max(ast.internal_imports + ast.external_imports, 1) * 100}%`, background: "#52c41a", height: "100%", borderRadius: 4 }} />
                                        <div style={{ width: `${ast.external_imports / Math.max(ast.internal_imports + ast.external_imports, 1) * 100}%`, background: "#1890ff", height: "100%", borderRadius: 4 }} />
                                    </div>
                                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginTop: 6 }}>
                                        <span><span style={{ color: "#52c41a" }}>■</span> Internal: {ast.internal_imports}</span>
                                        <span><span style={{ color: "#1890ff" }}>■</span> External: {ast.external_imports}</span>
                                    </div>
                                </div>
                            </div>
                            <div className="rs-card">
                                <div className="rs-card-title">🚪 Entry Points</div>
                                {ast.entry_points.slice(0, 8).map((ep, i) => (
                                    <div key={i} className="rs-entry-item">
                                        <span>{ep.endsWith(".rs") ? "🦀" : "📘"}</span>
                                        <code className="rs-entry-path">{ep}</code>
                                    </div>
                                ))}
                                {ast.entry_points.length > 8 && <div style={{ fontSize: 10, color: "#555", padding: 4 }}>+{ast.entry_points.length - 8} more</div>}
                            </div>
                            <div className="rs-card">
                                <div className="rs-card-title">📈 Most Connected Files</div>
                                {ast.top_importers.map(([file, count], i) => (
                                    <div key={i} className="rs-top-row">
                                        <span className="rs-top-rank">#{i + 1}</span>
                                        <code className="rs-top-file">{file.split('/').pop()}</code>
                                        <div className="rs-bar" style={{ flex: 1 }}>
                                            <div className="rs-bar-fill" style={{ width: `${(count / (ast.top_importers[0]?.[1] || 1)) * 100}%`, background: "#eb2f96" }} /></div>
                                        <span className="rs-top-count">{count}</span>
                                    </div>
                                ))}
                            </div>
                            <DatalogQueryPanel sbomPath={sbomPath} sourceRoot={rootDir} onHighlightProofChain={setGlowingPaths} />
                        </div>
                    )}

                    {/* ═══ MULTIGRAPH ═══ */}
                    {subTab === "multigraph" && (
                        <div className="rs-section">
                            {/* Layer Switcher */}
                            <div style={{ display: 'flex', gap: 4, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                                {LAYERS.map((l, i) => (
                                    <div key={l.key} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                        {i > 0 && i < LAYERS.length - 1 && <span style={{ color: '#333', fontSize: 14, fontWeight: 700 }}>▲</span>}
                                        {i === LAYERS.length - 1 && <span style={{ color: '#333', fontSize: 10, margin: '0 4px' }}>│</span>}
                                        <button onClick={() => switchLayer(l.key)}
                                            style={{
                                                padding: '5px 12px', borderRadius: 20, border: `2px solid ${activeLayer === l.key ? l.color : '#2a2a4a'}`,
                                                background: activeLayer === l.key ? `${l.color}22` : '#16162a', color: activeLayer === l.key ? l.color : '#8c8c8c',
                                                cursor: 'pointer', fontSize: 11, fontWeight: 700, transition: 'all .15s', display: 'flex', flexDirection: 'column', alignItems: 'center', lineHeight: 1.2,
                                                boxShadow: activeLayer === l.key ? `0 0 12px ${l.color}44` : 'none', minWidth: 80,
                                            }}>
                                            <span>{l.icon} {l.label} {l.count > 0 && <span style={{ fontSize: 8, opacity: 0.6 }}>({l.count})</span>}</span>
                                            <span style={{ fontSize: 8, fontWeight: 400, opacity: 0.5 }}>{l.sub}</span>
                                        </button>
                                    </div>
                                ))}
                                <div style={{ flex: 1 }} />
                                {/* Action buttons */}
                                <button className="rs-btn" onClick={buildMeta} disabled={loading} style={{ fontSize: 11, padding: '5px 12px', borderColor: '#52c41a', color: '#52c41a', background: '#52c41a11' }}>📦 Load SBOM</button>
                                <button className="rs-btn" onClick={buildTrust} disabled={loading || !sbomPath} style={{ fontSize: 11, padding: '5px 12px', borderColor: '#722ed1', color: '#b37feb', background: '#722ed111' }}>🛡️ Trust</button>
                                <button className="rs-btn" onClick={runExec} disabled={loading || !sbomPath} style={{ fontSize: 11, padding: '5px 12px', borderColor: '#1890ff', color: '#69c0ff', background: '#1890ff11' }}>⚙️ Exec</button>
                                <span style={{ width: 1, background: '#2a2a4a', margin: '0 4px', height: 28 }} />
                                <button onClick={() => setCveOverlay(v => !v)}
                                    style={{
                                        padding: '5px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, cursor: 'pointer', transition: 'all .15s',
                                        border: `2px solid ${cveOverlay ? '#ff4d4f' : '#2a2a4a'}`, background: cveOverlay ? '#ff4d4f22' : '#16162a',
                                        color: cveOverlay ? '#ff4d4f' : '#8c8c8c', boxShadow: cveOverlay ? '0 0 12px #ff4d4f44' : 'none'
                                    }}>
                                    🔴 CVE
                                </button>
                                <button onClick={() => setHeatmapMode(v => !v)}
                                    style={{
                                        padding: '5px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, cursor: 'pointer', transition: 'all .15s',
                                        border: `2px solid ${heatmapMode ? '#faad14' : '#2a2a4a'}`, background: heatmapMode ? '#faad1422' : '#16162a',
                                        color: heatmapMode ? '#faad14' : '#8c8c8c', boxShadow: heatmapMode ? '0 0 12px #faad1444' : 'none'
                                    }}>
                                    🌡️ Heat
                                </button>
                                {/* Graph Reasoning Presets */}
                                <select onChange={e => { if (e.target.value) { setGraphQuery(e.target.value); e.target.value = ''; } }}
                                    style={{ padding: '5px 8px', borderRadius: 20, border: '2px solid #2a2a4a', background: '#16162a', color: '#8c8c8c', fontSize: 11, cursor: 'pointer' }}>
                                    <option value="">📋 Presets</option>
                                    <option value="vuln">show vulnerable</option>
                                    <option value="critical">critical severity</option>
                                    <option value="unlicensed">no license</option>
                                    <option value="entry">entry points</option>
                                    <option value="supplier">no supplier</option>
                                </select>
                            </div>
                            {/* GraphQuery Bar */}
                            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                                <input className="rs-inp" style={{ flex: 1 }} value={graphQuery} onChange={e => { setGraphQuery(e.target.value); setPathHighlight(new Set()); setPathResult(null); }}
                                    placeholder="🔍 Search nodes, or trace: main.rs→CVE" onKeyDown={e => {
                                        if (e.key === 'Enter' && graphQuery.includes('→')) {
                                            const [f, t] = graphQuery.split('→').map(s => s.trim());
                                            if (f && t) tracePath(f, t);
                                        }
                                    }} />
                                <button onClick={() => {
                                    if (graphQuery.includes('→')) {
                                        const [f, t] = graphQuery.split('→').map(s => s.trim());
                                        if (f && t) tracePath(f, t);
                                    }
                                }} style={{ padding: '5px 12px', borderRadius: 20, border: '2px solid #52c41a', background: '#52c41a11', color: '#52c41a', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>
                                    🔎 Trace
                                </button>
                                {graphQuery && <button onClick={() => { setGraphQuery(""); setPathHighlight(new Set()); setPathResult(null); }} style={{ background: 'none', border: 'none', color: '#666', cursor: 'pointer', fontSize: 16 }}>✕</button>}
                                <span style={{ fontSize: 11, color: '#666', alignSelf: 'center', whiteSpace: 'nowrap' }}>{filteredGNodes.filter(n => !n.style?.opacity || (n.style?.opacity as number) > 0.5).length} / {gNodes.length} nodes</span>
                            </div>
                            {/* Path Result */}
                            {pathResult && (
                                <div style={{ marginBottom: 10, padding: '10px 14px', background: pathResult.found ? '#52c41a0a' : '#ff4d4f0a', border: `1px solid ${pathResult.found ? '#52c41a33' : '#ff4d4f33'}`, borderRadius: 10 }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                                        <span style={{ fontSize: 12, fontWeight: 700, color: pathResult.found ? '#52c41a' : '#ff4d4f' }}>
                                            {pathResult.found ? `✅ Path found (depth ${pathResult.depth})` : '❌ No path found'}
                                        </span>
                                        <span style={{ fontSize: 9, color: '#666' }}>⚡ {pathResult.query_duration_us}µs</span>
                                    </div>
                                    {pathResult.found && (
                                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                                            {pathResult.path.map((n, i) => {
                                                const lc: Record<string, string> = { ast: '#eb2f96', sbom: '#52c41a', build: '#fa8c16', exec: '#1890ff', trust: '#722ed1' };
                                                return (
                                                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                                        {i > 0 && <span style={{ color: '#444', fontSize: 10 }}>{pathResult.edge_types[i - 1] || '→'}</span>}
                                                        <span style={{ padding: '2px 8px', borderRadius: 12, border: `1px solid ${lc[n.layer] || '#666'}`, background: `${lc[n.layer] || '#666'}15`, fontSize: 10, color: lc[n.layer] || '#aaa', fontWeight: 600 }}>
                                                            {n.label} <span style={{ fontSize: 8, opacity: 0.6 }}>({n.kind})</span>
                                                        </span>
                                                    </span>
                                                );
                                            })}
                                        </div>
                                    )}
                                </div>
                            )}
                            {/* Layer Stats */}
                            {(metaGraph || trustData || execData) && (
                                <div className="rs-stats-row" style={{ marginBottom: 10 }}>
                                    {metaGraph && <>
                                        <div className="rs-stat-card"><div className="rs-stat-val">{metaGraph.stats.total_nodes}</div><div className="rs-stat-label">SBOM Nodes</div></div>
                                        <div className="rs-stat-card"><div className="rs-stat-val">{metaGraph.stats.ast_to_sbom_bridges}</div><div className="rs-stat-label">🌉 Bridges</div></div>
                                    </>}
                                    {trustData && <>
                                        <div className="rs-stat-card" style={{ borderColor: '#722ed1' }}><div className="rs-stat-val" style={{ color: '#722ed1' }}>{trustData.risk_summary.attack_paths}</div><div className="rs-stat-label">Attack Paths</div></div>
                                        <div className="rs-stat-card"><div className="rs-stat-val" style={{ color: trustData.risk_summary.supply_chain_risk === 'CRITICAL' ? '#ff4d4f' : '#fa8c16' }}>{trustData.risk_summary.supply_chain_risk}</div><div className="rs-stat-label">Supply Risk</div></div>
                                    </>}
                                    {execData && <>
                                        <div className="rs-stat-card"><div className="rs-stat-val" style={{ color: execData.verdict === 'PASS' ? '#52c41a' : '#ff4d4f' }}>{execData.verdict}</div><div className="rs-stat-label">Pipeline</div></div>
                                        <div className="rs-stat-card"><div className="rs-stat-val">{execData.total_duration_us}µs</div><div className="rs-stat-label">Duration</div></div>
                                    </>}
                                </div>
                            )}
                            {/* Unified ReactFlow Canvas */}
                            <div style={{ height: 700, border: '1px solid #2a2a4a', borderRadius: 12, overflow: 'hidden', position: 'relative' }}>
                                <ReactFlow nodes={filteredGNodes} edges={filteredGEdges} onNodesChange={onGNodesChange} onEdgesChange={onGEdgesChange}
                                    nodeTypes={nodeTypes} fitView minZoom={0.02} maxZoom={3}
                                    proOptions={{ hideAttribution: true }} style={{ background: '#08081a' }} defaultEdgeOptions={{ type: 'smoothstep' }}>
                                    <Background color="#1a1a30" gap={30} size={1} />
                                    <Controls style={{ background: '#16162a', borderColor: '#2a2a4a', borderRadius: 8 }} />
                                    <MiniMap maskColor="#08081a88" style={{ background: '#16162a', borderRadius: 8, border: '1px solid #2a2a4a' }}
                                        nodeColor={(n: Node) => {
                                            const t = n.type || '';
                                            if (t === 'metaVuln' || t === 'trustNode') return '#ff4d4f';
                                            if (t === 'metaComp') return '#722ed1';
                                            if (t === 'metaMod' || t === 'execStep') return '#1890ff';
                                            if (t === 'buildStep') return '#fa8c16';
                                            if (t === 'eaExternal') return '#1890ff';
                                            if (t === 'eaDir') return '#ffffff22';
                                            const d = n.data as EaNodeData;
                                            return LANG_META[d?.language]?.color || '#666';
                                        }} />
                                    <Panel position="top-left">
                                        <div className="ea-legend">
                                            <span className="ea-legend-title">{LAYERS.find(l => l.key === activeLayer)?.icon} {LAYERS.find(l => l.key === activeLayer)?.label} Layer</span>
                                            {activeLayer === 'ast' && <>
                                                {Object.entries(LANG_META).filter(([l]) => ast?.languages[l]).map(([lang, m]) => (
                                                    <span key={lang} className="ea-legend-item"><span className="ea-legend-dot" style={{ background: m.color }} />{m.icon} {lang}</span>
                                                ))}
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#52c41a' }} />import</span>
                                            </>}
                                            {activeLayer === 'sbom' && <>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#dea584' }} />📄 Files</span>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#1890ff' }} />📦 Modules</span>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#722ed1' }} />🧩 Components</span>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#ff4d4f' }} />⚠️ Vulns</span>
                                            </>}
                                            {activeLayer === 'trust' && <>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#722ed1' }} />depends_on</span>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#ff4d4f' }} />has_vuln</span>
                                                <span className="ea-legend-item"><span className="ea-legend-dot" style={{ background: '#13c2c2' }} />licensed_by</span>
                                            </>}
                                            <span className="ea-legend-sep" />
                                            <span className="ea-legend-item" style={{ color: '#666' }}>{gNodes.length} nodes · {gEdges.length} edges</span>
                                        </div>
                                    </Panel>
                                </ReactFlow>

                                <QueryLabPanel
                                    rootDir={rootDir}
                                    sbomPath={sbomPath || ""}
                                    onPathsFound={setGlowingPaths}
                                />
                            </div>
                        </div>
                    )}

                    {/* ─── SECURITY QUERIES ─── */}
                    {subTab === "security" && (
                        <div className="rs-section">
                            <div className="rs-cards-row" style={{ flexWrap: 'wrap' }}>
                                {/* CVE Impact */}
                                <div className="rs-card" style={{ flex: '1 1 300px' }}>
                                    <div className="rs-card-title" style={{ color: '#ff4d4f' }}>🔴 CVE Impact Analysis</div>
                                    <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                                        <input className="rs-inp" style={{ flex: 1 }} value={cveId} onChange={e => setCveId(e.target.value)} placeholder="CVE-2024-XXXX" />
                                        <button className="rs-btn" onClick={queryCve} style={{ borderColor: '#ff4d4f', color: '#ff7875', background: '#ff4d4f22' }}>Analyze</button>
                                    </div>
                                    {cveResult && (
                                        <div className="sec-result">
                                            <div className="sec-kv"><span>CVE</span><span style={{ color: '#ff4d4f', fontWeight: 700 }}>{cveResult.cve_id}</span></div>
                                            <div className="sec-kv"><span>Severity</span><span style={{ color: cveResult.severity === 'CRITICAL' ? '#ff4d4f' : cveResult.severity === 'HIGH' ? '#fa8c16' : '#faad14' }}>{cveResult.severity}</span></div>
                                            <div className="sec-kv"><span>Score</span><span>{cveResult.score}</span></div>
                                            <div className="sec-kv"><span>Blast Radius</span><span style={{ color: '#ff4d4f', fontWeight: 700 }}>{cveResult.blast_radius}</span></div>
                                            <div className="sec-kv"><span>Affected Components</span><span>{cveResult.affected_components.length}</span></div>
                                            <div className="sec-kv"><span>Affected Files</span><span>{cveResult.affected_files.length}</span></div>
                                            <div className="sec-kv"><span>Exposed Entry Points</span><span style={{ color: '#ff4d4f' }}>{cveResult.entry_points.length}</span></div>
                                            {cveResult.affected_components.map((c, i) => <div key={i} className="sec-item">🧩 {c.label} <span style={{ color: '#666', fontSize: 10 }}>{c.properties.version || ''}</span></div>)}
                                            {cveResult.entry_points.map((e, i) => <div key={i} className="sec-item" style={{ color: '#ff7875' }}>🚪 {e.label}</div>)}
                                        </div>
                                    )}
                                </div>
                                {/* Supply Chain Trace */}
                                <div className="rs-card" style={{ flex: '1 1 300px' }}>
                                    <div className="rs-card-title" style={{ color: '#1890ff' }}>🔗 Supply Chain Trace</div>
                                    <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                                        <input className="rs-inp" style={{ flex: 1 }} value={pkgName} onChange={e => setPkgName(e.target.value)} placeholder="Package name (e.g. serde)" />
                                        <button className="rs-btn" onClick={queryTrace} style={{ borderColor: '#1890ff', color: '#69c0ff', background: '#1890ff22' }}>Trace</button>
                                    </div>
                                    {traceResult && (
                                        <div className="sec-result">
                                            <div className="sec-kv"><span>Package</span><span style={{ color: '#1890ff', fontWeight: 700 }}>{traceResult.package_name}</span></div>
                                            <div className="sec-kv"><span>Importing Files</span><span>{traceResult.importing_files.length}</span></div>
                                            <div className="sec-kv"><span>SBOM Component</span><span>{traceResult.sbom_component ? '✅ ' + traceResult.sbom_component.label : '❌ Not found'}</span></div>
                                            <div className="sec-kv"><span>Transitive Deps</span><span>{traceResult.transitive_deps.length}</span></div>
                                            <div className="sec-kv"><span>Vulnerabilities</span><span style={{ color: traceResult.vulnerabilities.length > 0 ? '#ff4d4f' : '#52c41a' }}>{traceResult.vulnerabilities.length}</span></div>
                                            {traceResult.importing_files.slice(0, 5).map((f, i) => <div key={i} className="sec-item">📄 {f.label}</div>)}
                                            {traceResult.vulnerabilities.map((v, i) => <div key={i} className="sec-item" style={{ color: '#ff7875' }}>⚠️ {v.label} ({v.properties.severity})</div>)}
                                        </div>
                                    )}
                                </div>
                                {/* Attack Surface */}
                                <div className="rs-card" style={{ flex: '1 1 300px' }}>
                                    <div className="rs-card-title" style={{ color: '#fa8c16' }}>💥 Attack Surface</div>
                                    <button className="rs-btn" onClick={queryAttack} style={{ borderColor: '#fa8c16', color: '#ffc069', background: '#fa8c1622', marginBottom: 8, width: '100%' }}>Analyze Attack Surface</button>
                                    {attackResult && (
                                        <div className="sec-result">
                                            <div className="sec-kv"><span>Vuln Components</span><span style={{ color: '#ff4d4f', fontWeight: 700 }}>{attackResult.vuln_component_count}</span></div>
                                            <div className="sec-kv"><span>Exposed Entry Points</span><span style={{ color: '#fa8c16', fontWeight: 700 }}>{attackResult.exposed_entry_count}</span></div>
                                            <div className="sec-kv"><span>Risk Paths</span><span>{attackResult.risk_paths.length}</span></div>
                                            {attackResult.exposed_entries.slice(0, 8).map((e, i) => <div key={i} className="sec-item" style={{ color: '#ffc069' }}>🚪 {e.label}</div>)}
                                            {attackResult.risk_paths.slice(0, 5).map((rp, i) => <div key={i} className="sec-item" style={{ fontSize: 10, color: '#888' }}>🔗 {rp.from_vuln_component.replace('component:', '')} → {rp.nodes.length} hops</div>)}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ─── IMPORTS ─── */}
                    {subTab === "imports" && cg && (
                        <div className="rs-section">
                            <div className="rs-filter-row">
                                <select className="rs-sel" value={filterImport} onChange={e => setFilterImport(e.target.value)}>
                                    <option value="all">All ({cg.import_edges.length})</option>
                                    <option value="internal">Internal ({cg.import_edges.filter(e => e.import_type === "internal").length})</option>
                                    <option value="external">External ({cg.import_edges.filter(e => e.import_type === "external").length})</option>
                                    <option value="stdlib">Stdlib ({cg.import_edges.filter(e => e.import_type === "stdlib").length})</option>
                                </select>
                                <span style={{ fontSize: 11, color: "#666" }}>Showing {filteredImports.length} imports</span>
                            </div>
                            <div className="rs-card" style={{ maxHeight: 500, overflowY: "auto" }}>
                                <div className="rs-card-title">🔗 Import Edges</div>
                                {filteredImports.slice(0, 100).map((e, i) => (
                                    <div key={i} className="rs-import-edge-row">
                                        <code className="rs-ie-file">{e.from_file.split('/').pop()}</code>
                                        <span className="rs-ie-type" style={{ color: ({ internal: "#52c41a", external: "#1890ff", stdlib: "#fa8c16" })[e.import_type] || "#666" }}>{e.import_type}</span>
                                        <code className="rs-ie-module">{e.to_module}</code>
                                    </div>
                                ))}
                                {filteredImports.length > 100 && <div style={{ fontSize: 10, color: "#555", padding: 8, textAlign: "center" }}>+{filteredImports.length - 100} more</div>}
                            </div>
                        </div>
                    )}

                    {/* ─── DEPS ─── */}
                    {subTab === "deps" && cg && (
                        <div className="rs-section">
                            <div className="rs-stats-row">
                                <div className="rs-stat-card"><div className="rs-stat-val">{ast.declared_deps}</div><div className="rs-stat-label">Declared</div></div>
                                <div className="rs-stat-card"><div className="rs-stat-val">{r?.build.resolved_deps || 0}</div><div className="rs-stat-label">Resolved</div></div>
                                <div className="rs-stat-card"><div className="rs-stat-val">{ast.build_systems.length}</div><div className="rs-stat-label">Build Systems</div></div>
                            </div>
                            {cg.build_files.map((bf, bi) => (
                                <div key={bi} className="rs-card">
                                    <div className="rs-card-title">{bf.build_system === "cargo" ? "🦀" : "📦"} {bf.path} — {bf.declared_deps.length} deps</div>
                                    {bf.declared_deps.map((dep, di) => (
                                        <div key={di} className="rs-dep-row">
                                            <span className="rs-dep-name">{dep.name}</span>
                                            <code className="rs-dep-ver">{dep.version}</code>
                                            <span className="rs-dep-type" style={{ color: ({ runtime: "#52c41a", dev: "#1890ff", build: "#fa8c16", optional: "#722ed1" })[dep.dep_type] || "#666" }}>{dep.dep_type}</span>
                                        </div>
                                    ))}
                                </div>
                            ))}
                        </div>
                    )}

                    {/* ─── BUILD ─── */}
                    {subTab === "build" && (
                        <div className="rs-section">
                            <div className="rs-cards-row">
                                <div className="rs-card" style={{ flex: 1 }}>
                                    <div className="rs-card-title">🎯 Build Targets</div>
                                    <div className="rs-kv"><span>Targets</span><span>{r?.build.targets || 0}</span></div>
                                    <div className="rs-kv"><span>Steps</span><span>{r?.build.build_steps || 0}</span></div>
                                    <div className="rs-kv"><span>Outputs</span><span>{r?.build.outputs || 0}</span></div>
                                </div>
                                <div className="rs-card" style={{ flex: 1 }}>
                                    <div className="rs-card-title">🔧 Commands</div>
                                    {r?.build.build_commands.map((cmd, i) => (
                                        <div key={i} className="rs-cmd"><code>{cmd}</code></div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}
                </>
            )}

            {!r && !loading && (
                <div className="rs-empty">
                    <div style={{ fontSize: 56 }}>🦀</div>
                    <div style={{ fontSize: 18, fontWeight: 700, margin: "12px 0 6px" }}>Code Intelligence</div>
                    <div style={{ color: "#666", maxWidth: 520, lineHeight: 1.7 }}>
                        Parse project source → build <strong>Code Graph</strong> → discover import relationships<br /><br />
                        <strong>Languages:</strong> Rust, TypeScript, JavaScript, Java, Go, Python, C/C++, Kotlin, Ruby, C#<br />
                        <strong>Features:</strong> Import graph · Dependency extraction · Coupling analysis · Entry point detection
                    </div>
                </div>
            )}

            <style>{`
                /* ── EA-style Source Node ── */
                .ea-node{border:2px solid;border-radius:10px;overflow:hidden;min-width:160px;max-width:200px;font-family:'Inter',system-ui,sans-serif;user-select:none;transition:transform .15s,box-shadow .15s}
                .ea-node:hover{transform:translateY(-2px);z-index:10}
                .ea-header{display:flex;align-items:center;gap:6px;padding:6px 10px;border-bottom:1px solid}
                .ea-icon{font-size:14px}
                .ea-title{font-size:11px;font-weight:700;color:#e0e0e0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
                .ea-entry-badge{font-size:7px;padding:1px 4px;border-radius:3px;background:#ffffff22;color:#fff;font-weight:800;letter-spacing:1px}
                .ea-body{padding:4px 10px}
                .ea-attr{display:flex;align-items:center;gap:4px;font-size:10px;color:#8c8c8c;padding:1px 0}
                .ea-attr-icon{font-size:10px;width:14px;text-align:center}
                .ea-footer{padding:3px 10px;font-size:9px;text-align:center;border-top:1px solid;text-transform:uppercase;letter-spacing:1px}
                /* ── EA External Module ── */
                .ea-ext-node{background:#1890ff0a;border:1px dashed #1890ff55;border-radius:8px;padding:6px 10px;min-width:100px}
                .ea-ext-header{display:flex;align-items:center;gap:4px;font-size:10px;color:#69c0ff;font-weight:600}
                .ea-ext-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:90px}
                .ea-ext-count{font-size:8px;color:#1890ff88;margin-top:2px}
                /* ── EA Dir Label ── */
                .ea-dir-node{padding:4px 12px;background:#ffffff06;border:1px solid #ffffff11;border-radius:6px}
                .ea-dir-header{display:flex;align-items:center;gap:6px;font-size:10px;color:#8c8c8c;font-weight:600}
                .ea-dir-count{font-size:9px;color:#555;margin-left:auto;background:#ffffff08;padding:0 4px;border-radius:3px}
                /* ── Legend Panel ── */
                .ea-legend{display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px;background:#16162aee;border:1px solid #2a2a4a;border-radius:8px;backdrop-filter:blur(8px);max-width:300px;align-items:center}
                .ea-legend-title{font-size:10px;font-weight:700;color:#e0e0e0;width:100%;margin-bottom:2px}
                .ea-legend-item{display:flex;align-items:center;gap:3px;font-size:9px;color:#8c8c8c}
                .ea-legend-dot{width:6px;height:6px;border-radius:50%;display:inline-block}
                .ea-legend-sep{width:100%;height:1px;background:#2a2a4a}
                /* ── Handles ── */
                .ea-handle{width:6px!important;height:6px!important;background:#2a2a4a!important;border:1px solid #444!important}
                /* ── Form & shared ── */
                .rs-badge{font-size:10px;color:#eb2f96;background:#eb2f9618;padding:3px 10px;border-radius:12px}
                .rs-time-badge{font-size:10px;color:#52c41a;background:#52c41a18;padding:3px 10px;border-radius:12px;font-weight:700;font-family:monospace}
                .rs-form{display:flex;gap:8px;padding:14px;background:#16162a;border:1px solid #2a2a4a;border-radius:12px;margin-bottom:14px}
                .rs-inp{padding:10px 14px;background:#0e0e1a;border:1px solid #333;border-radius:8px;color:#e0e0e0;font-family:monospace;font-size:13px;outline:none}
                .rs-inp:focus{border-color:#eb2f96}
                .rs-btn{padding:10px 20px;border-radius:8px;border:1px solid #eb2f96;background:#eb2f9622;color:#ff85c0;cursor:pointer;font-size:13px;font-weight:600;white-space:nowrap;transition:background .15s}
                .rs-btn:disabled{opacity:.5}.rs-btn:hover:not(:disabled){background:#eb2f9644}
                .rs-tabs{display:flex;gap:4px;margin-bottom:14px}
                .rs-tab{padding:8px 16px;border:1px solid #2a2a4a;border-radius:8px;background:transparent;color:#8c8c8c;cursor:pointer;font-size:12px;transition:all .15s}
                .rs-tab:hover{color:#e0e0e0}.rs-tab.active{background:#16162a;color:#e0e0e0;border-color:#eb2f96}
                .rs-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
                .rs-card{background:#16162a;border:1px solid #2a2a4a;border-radius:10px;padding:14px}
                .rs-card-wide{grid-column:1/-1}
                .rs-card-title{font-size:12px;font-weight:700;color:#e0e0e0;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #2a2a4a}
                .rs-stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px}
                .rs-stat{text-align:center;padding:8px;background:#0e0e1a;border-radius:8px}
                .rs-stat-val{font-size:22px;font-weight:800;color:#e0e0e0}
                .rs-stat-label{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
                .rs-lang-row{display:flex;align-items:center;gap:8px;padding:4px 0}
                .rs-lang-name{width:80px;font-size:12px;color:#b8b8cc;font-weight:600}
                .rs-bar{flex:1;height:6px;background:#0e0e1a;border-radius:3px;overflow:hidden}
                .rs-bar-fill{height:100%;border-radius:3px;transition:width .3s}
                .rs-lang-count{font-size:10px;color:#666;white-space:nowrap}
                .rs-import-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;gap:2px}
                .rs-entry-item{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #1a1a30}
                .rs-entry-path{font-size:11px;color:#eb2f96}
                .rs-top-row{display:flex;align-items:center;gap:8px;padding:3px 0}
                .rs-top-rank{font-size:10px;color:#555;width:24px}
                .rs-top-file{font-size:11px;color:#b8b8cc;width:120px;overflow:hidden;text-overflow:ellipsis}
                .rs-top-count{font-size:11px;color:#eb2f96;font-weight:700;width:30px;text-align:right}
                .rs-section{display:flex;flex-direction:column;gap:12px}
                .rs-filter-row{display:flex;gap:8px;margin-bottom:4px;align-items:center}
                .rs-sel{padding:6px 8px;background:#0e0e1a;border:1px solid #333;border-radius:6px;color:#e0e0e0;font-size:12px}
                .rs-import-edge-row{display:flex;align-items:center;gap:8px;padding:3px 0;border-bottom:1px solid #1a1a30;font-size:11px}
                .rs-ie-file{color:#b8b8cc;width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
                .rs-ie-type{font-size:9px;padding:1px 4px;border-radius:3px;background:#ffffff08;min-width:50px;text-align:center}
                .rs-ie-module{color:#eb2f96;flex:1}
                .rs-stats-row{display:flex;gap:12px;margin-bottom:12px}
                .rs-stat-card{flex:1;text-align:center;padding:16px;background:#16162a;border:1px solid #2a2a4a;border-radius:10px}
                .rs-dep-row{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #1a1a30;font-size:12px}
                .rs-dep-name{flex:1;color:#e0e0e0;font-weight:600}
                .rs-dep-ver{color:#8c8c8c;font-size:11px}
                .rs-dep-type{font-size:10px;text-transform:uppercase;letter-spacing:0.5px}
                .rs-cards-row{display:flex;gap:12px}
                .rs-kv{display:flex;justify-content:space-between;padding:5px 0;font-size:12px;border-bottom:1px solid #1a1a30}
                .rs-kv span:first-child{color:#8c8c8c}.rs-kv span:last-child{color:#e0e0e0;font-family:monospace}
                .rs-cmd{padding:5px 0;border-bottom:1px solid #1a1a30}
                .rs-cmd code{color:#fa8c16;background:#fa8c1610;padding:2px 6px;border-radius:4px;font-size:12px}
                .rs-empty{text-align:center;padding:80px 20px;color:#666}
                .react-flow__controls button{background:#16162a!important;border-color:#2a2a4a!important;color:#e0e0e0!important}
                /* ── Security Queries ── */
                .sec-result{margin-top:8px;border-top:1px solid #2a2a4a;padding-top:8px}
                .sec-kv{display:flex;justify-content:space-between;padding:3px 0;font-size:11px;border-bottom:1px solid #1a1a30}
                .sec-kv span:first-child{color:#8c8c8c}
                .sec-kv span:last-child{color:#e0e0e0;font-family:monospace}
                .sec-item{padding:2px 0;font-size:10px;color:#b8b8cc}
                /* ── Meta Nodes ── */
                .meta-comp-node{background:#722ed108;border:2px solid #722ed1;border-radius:10px;padding:8px 12px;min-width:120px}
                .meta-comp-title{font-size:11px;font-weight:700;color:#b37feb}
                .meta-comp-detail{font-size:9px;color:#666;margin-top:2px}
                .meta-vuln-node{background:#ff4d4f0a;border:2px solid #ff4d4f;border-radius:10px;padding:8px 12px;min-width:100px}
                .meta-vuln-title{font-size:11px;font-weight:700;color:#ff7875}
                .meta-vuln-detail{font-size:9px;margin-top:2px}
                .meta-mod-node{background:#1890ff0a;border:1px dashed #1890ff66;border-radius:8px;padding:6px 10px;min-width:90px}
                .meta-mod-title{font-size:10px;font-weight:600;color:#69c0ff}
                .meta-mod-detail{font-size:8px;color:#1890ff88}
            `}</style>
        </div>
    );
}
