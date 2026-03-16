import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import DropZone from "./DropZone";

interface BomSummary {
    bomFormat: string;
    specVersion: string;
    version: number;
    serialNumber?: string;
    componentsCount: number;
    vulnerabilitiesCount: number;
    dependenciesCount: number;
    licenses: { id: string; count: number }[];
}

interface TreeNode {
    key: string;
    value: any;
    type: string;
    children?: TreeNode[];
    expanded?: boolean;
}

function buildTree(obj: any, parentKey = ""): TreeNode[] {
    if (obj === null || obj === undefined) return [];
    if (Array.isArray(obj)) {
        return obj.map((item, i) => {
            const key = `${parentKey}[${i}]`;
            const type = typeof item;
            if (type === "object" && item !== null) {
                return { key, value: item, type: "object", children: buildTree(item, key), expanded: false };
            }
            return { key, value: item, type };
        });
    }
    if (typeof obj === "object") {
        return Object.entries(obj).map(([k, v]) => {
            const key = parentKey ? `${parentKey}.${k}` : k;
            const type = typeof v;
            if (Array.isArray(v)) {
                return { key: k, value: v, type: "array", children: buildTree(v, key), expanded: false };
            }
            if (type === "object" && v !== null) {
                return { key: k, value: v, type: "object", children: buildTree(v, key), expanded: false };
            }
            return { key: k, value: v, type };
        });
    }
    return [];
}

function extractSummary(data: any): BomSummary | null {
    if (!data || typeof data !== "object") return null;
    const components = data.components || [];
    const vulns = data.vulnerabilities || [];
    const deps = data.dependencies || [];

    // Count licenses
    const licMap = new Map<string, number>();
    for (const c of components) {
        const lics = c.licenses || [];
        for (const l of lics) {
            const id = l?.license?.id || l?.license?.name || l?.expression || "Unknown";
            licMap.set(id, (licMap.get(id) || 0) + 1);
        }
    }
    const licenses = Array.from(licMap.entries())
        .map(([id, count]) => ({ id, count }))
        .sort((a, b) => b.count - a.count);

    return {
        bomFormat: data.bomFormat || "Unknown",
        specVersion: data.specVersion || "?",
        version: data.version || 0,
        serialNumber: data.serialNumber,
        componentsCount: components.length,
        vulnerabilitiesCount: vulns.length,
        dependenciesCount: deps.length,
        licenses,
    };
}

function TreeView({ nodes, depth = 0 }: { nodes: TreeNode[]; depth?: number }) {
    const [expanded, setExpanded] = useState<Set<string>>(new Set());

    const toggle = (key: string) => {
        setExpanded((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    };

    return (
        <div className="json-tree" style={{ paddingLeft: depth > 0 ? 16 : 0 }}>
            {nodes.map((node) => {
                const hasChildren = node.children && node.children.length > 0;
                const isOpen = expanded.has(node.key);
                const displayKey = node.key.includes(".") ? node.key.split(".").pop() : node.key;

                return (
                    <div key={node.key} className="json-tree-node">
                        <div
                            className={`json-tree-row ${hasChildren ? "json-tree-expandable" : ""}`}
                            onClick={() => hasChildren && toggle(node.key)}
                        >
                            {hasChildren && (
                                <span className={`json-tree-arrow ${isOpen ? "open" : ""}`}>▶</span>
                            )}
                            <span className="json-key">{displayKey}</span>
                            {!hasChildren && (
                                <>
                                    <span className="json-colon">: </span>
                                    <span className={`json-value json-value-${node.type}`}>
                                        {node.type === "string"
                                            ? `"${String(node.value).slice(0, 120)}${String(node.value).length > 120 ? "…" : ""}"`
                                            : String(node.value)}
                                    </span>
                                </>
                            )}
                            {hasChildren && !isOpen && (
                                <span className="json-preview">
                                    {node.type === "array"
                                        ? `[${node.children!.length} items]`
                                        : `{${node.children!.length} keys}`}
                                </span>
                            )}
                        </div>
                        {hasChildren && isOpen && (
                            <TreeView nodes={node.children!} depth={depth + 1} />
                        )}
                    </div>
                );
            })}
        </div>
    );
}

export default function JsonViewer() {
    const [data, setData] = useState<any>(null);
    const [summary, setSummary] = useState<BomSummary | null>(null);
    const [tree, setTree] = useState<TreeNode[]>([]);
    const [filePath, setFilePath] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const loadFile = useCallback(async (path: string) => {
        setLoading(true);
        setError(null);
        try {
            const content = await invoke<string>("read_file_contents", { path });
            const parsed = JSON.parse(content);
            setData(parsed);
            setSummary(extractSummary(parsed));
            setTree(buildTree(parsed));
            setFilePath(path);
        } catch (err: any) {
            setError(err?.toString?.() ?? String(err));
            setData(null);
            setSummary(null);
            setTree([]);
        }
        setLoading(false);
    }, []);

    const openFile = useCallback(async () => {
        const file = await open({
            multiple: false,
            filters: [
                { name: "JSON Files", extensions: ["json"] },
                { name: "All Files", extensions: ["*"] },
            ],
        });
        if (file) {
            loadFile(file as string);
        }
    }, [loadFile]);

    const handleDrop = useCallback(
        (path: string) => {
            loadFile(path);
        },
        [loadFile]
    );

    return (
        <div className="json-viewer-panel">
            {!data ? (
                <DropZone onFileDrop={handleDrop} className="json-drop-full">
                    <div className="json-empty">
                        <span className="json-empty-icon">📄</span>
                        <h3>JSON BOM Viewer</h3>
                        <p>Drag & drop a CycloneDX JSON file here, or</p>
                        <button className="exec-btn json-open-btn" onClick={openFile} disabled={loading}>
                            {loading ? (
                                <>
                                    <span className="spinner" /> Loading…
                                </>
                            ) : (
                                <>📂 Open File</>
                            )}
                        </button>
                        {error && <div className="json-error">{error}</div>}
                    </div>
                </DropZone>
            ) : (
                <div className="json-loaded">
                    {/* File bar */}
                    <div className="json-file-bar">
                        <span className="json-file-path" title={filePath || ""}>
                            📄 {filePath?.split("/").pop() || "file.json"}
                        </span>
                        <button className="preset-btn" onClick={openFile}>
                            Open Another
                        </button>
                        <button
                            className="preset-btn"
                            onClick={() => {
                                setData(null);
                                setSummary(null);
                                setTree([]);
                                setFilePath(null);
                            }}
                        >
                            Close
                        </button>
                    </div>

                    {/* Summary cards */}
                    {summary && (
                        <div className="json-summary-cards">
                            <div className="json-card">
                                <span className="json-card-value">{summary.bomFormat}</span>
                                <span className="json-card-label">Format</span>
                            </div>
                            <div className="json-card">
                                <span className="json-card-value">{summary.specVersion}</span>
                                <span className="json-card-label">Spec Version</span>
                            </div>
                            <div className="json-card">
                                <span className="json-card-value">{summary.componentsCount}</span>
                                <span className="json-card-label">Components</span>
                            </div>
                            <div className="json-card json-card-warn">
                                <span className="json-card-value">{summary.vulnerabilitiesCount}</span>
                                <span className="json-card-label">Vulnerabilities</span>
                            </div>
                            <div className="json-card">
                                <span className="json-card-value">{summary.dependenciesCount}</span>
                                <span className="json-card-label">Dependencies</span>
                            </div>
                            <div className="json-card">
                                <span className="json-card-value">{summary.licenses.length}</span>
                                <span className="json-card-label">License Types</span>
                            </div>
                        </div>
                    )}

                    {/* License breakdown */}
                    {summary && summary.licenses.length > 0 && (
                        <div className="json-licenses">
                            <h4>License Distribution</h4>
                            <div className="json-license-list">
                                {summary.licenses.slice(0, 15).map((l) => (
                                    <div key={l.id} className="json-license-item">
                                        <span className="json-license-bar-fill"
                                            style={{ width: `${Math.min(100, (l.count / summary.componentsCount) * 100)}%` }}
                                        />
                                        <span className="json-license-id">{l.id}</span>
                                        <span className="json-license-count">{l.count}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Tree view */}
                    <div className="json-tree-container">
                        <h4>Document Tree</h4>
                        <div className="json-tree-scroll">
                            <TreeView nodes={tree} />
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
