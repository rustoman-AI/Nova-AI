import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface ExecResult {
    success: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    tool: string;
}

interface BomComponent {
    type?: string;
    name?: string;
    version?: string;
    group?: string;
    components?: BomComponent[];
}

interface MergedBom {
    metadata?: { component?: BomComponent };
    components?: BomComponent[];
}

export default function MergeVisualizer() {
    const [inputFiles, setInputFiles] = useState<string[]>([]);
    const [hierarchical, setHierarchical] = useState(true);
    const [groupName, setGroupName] = useState("");
    const [appName, setAppName] = useState("merged-app");
    const [appVersion, setAppVersion] = useState("1.0.0");
    const [isRunning, setIsRunning] = useState(false);
    const [result, setResult] = useState<ExecResult | null>(null);
    const [mergedTree, setMergedTree] = useState<MergedBom | null>(null);

    const addFiles = useCallback(async () => {
        const files = await open({
            multiple: true,
            filters: [{ name: "CycloneDX BOM", extensions: ["json", "xml"] }],
            title: "Select BOM files to merge",
        });
        if (files) {
            const arr = Array.isArray(files) ? files : [files];
            setInputFiles(prev => [...prev, ...arr.filter(f => !prev.includes(f))]);
        }
    }, []);

    const removeFile = useCallback((path: string) => {
        setInputFiles(prev => prev.filter(f => f !== path));
    }, []);

    const handleMerge = useCallback(async () => {
        if (inputFiles.length < 2) return;
        const outPath = await save({
            defaultPath: `merged-bom.json`,
            filters: [{ name: "CycloneDX JSON", extensions: ["json"] }],
        });
        if (!outPath) return;

        setIsRunning(true);
        setResult(null);
        setMergedTree(null);

        const args: string[] = ["merge"];
        for (const f of inputFiles) {
            args.push("--input-file", f);
        }
        args.push("--output-file", outPath as string);
        args.push("--output-format", "json");

        if (hierarchical) {
            args.push("--hierarchical");
            if (appName) args.push("--name", appName);
            if (appVersion) args.push("--version", appVersion);
            if (groupName) args.push("--group", groupName);
        }

        try {
            const res = await invoke<ExecResult>("run_sidecar", { name: "cyclonedx", args });
            setResult(res);

            // If successful, load and parse the merged BOM for tree view
            if (res.success) {
                try {
                    const content = await invoke<string>("read_file_contents", { path: outPath });
                    const bom: MergedBom = JSON.parse(content);
                    setMergedTree(bom);
                } catch { /* parsing optional */ }
            }
        } catch (err: any) {
            setResult({ success: false, exit_code: -1, stdout: "", stderr: String(err), tool: "cyclonedx" });
        }
        setIsRunning(false);
    }, [inputFiles, hierarchical, appName, appVersion, groupName]);

    // Detect version conflicts across all components
    const conflicts = useMemo(() => {
        if (!mergedTree) return new Map<string, string[]>();
        const byName = new Map<string, Set<string>>();

        function walk(components: BomComponent[] | undefined) {
            if (!components) return;
            for (const c of components) {
                const key = c.group ? `${c.group}/${c.name}` : (c.name || "?");
                if (!byName.has(key)) byName.set(key, new Set());
                if (c.version) byName.get(key)!.add(c.version);
                walk(c.components);
            }
        }
        walk(mergedTree.components);

        const result = new Map<string, string[]>();
        for (const [name, versions] of byName) {
            if (versions.size > 1) result.set(name, [...versions].sort());
        }
        return result;
    }, [mergedTree]);

    return (
        <div className="merge-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Merge & Visualize</h2>
                <button className="exec-btn" onClick={addFiles}>📁 Add BOMs</button>
            </div>

            {/* File list */}
            {inputFiles.length > 0 && (
                <div className="merge-files">
                    {inputFiles.map((f, i) => (
                        <div key={i} className="merge-file-row">
                            <span className="merge-file-idx">{i + 1}</span>
                            <span className="merge-file-name">{f.split("/").pop()}</span>
                            <button className="merge-file-rm" onClick={() => removeFile(f)}>✕</button>
                        </div>
                    ))}
                </div>
            )}

            {/* Options */}
            {inputFiles.length >= 2 && (
                <div className="crypto-card">
                    <div className="merge-mode-row">
                        <button
                            className={`crypto-mode-btn ${!hierarchical ? "crypto-mode-active" : ""}`}
                            onClick={() => setHierarchical(false)}
                        >📋 Flat Merge</button>
                        <button
                            className={`crypto-mode-btn ${hierarchical ? "crypto-mode-active" : ""}`}
                            onClick={() => setHierarchical(true)}
                        >🌳 Hierarchical Merge</button>
                    </div>

                    {hierarchical && (
                        <div className="merge-hier-fields">
                            <div className="crypto-field">
                                <label className="settings-label">Application Name *</label>
                                <input className="settings-input" value={appName} onChange={e => setAppName(e.target.value)} />
                            </div>
                            <div className="crypto-field">
                                <label className="settings-label">Version *</label>
                                <input className="settings-input" value={appVersion} onChange={e => setAppVersion(e.target.value)} />
                            </div>
                            <div className="crypto-field">
                                <label className="settings-label">Group (optional)</label>
                                <input className="settings-input" value={groupName} onChange={e => setGroupName(e.target.value)} placeholder="com.example" />
                            </div>
                        </div>
                    )}

                    <div className="crypto-actions">
                        <button className="exec-btn" onClick={handleMerge} disabled={isRunning}>
                            {isRunning ? <><span className="spinner" /> Merging...</> : `🔀 Merge ${inputFiles.length} BOMs`}
                        </button>
                    </div>
                </div>
            )}

            {/* Result */}
            {result && (
                <div className={`crypto-result fade-in ${result.success ? "crypto-result-ok" : "crypto-result-err"}`}>
                    <div className="crypto-result-header">
                        {result.success ? `✅ Merged ${inputFiles.length} BOMs` : `❌ Failed (exit ${result.exit_code})`}
                    </div>
                    {result.stdout.trim() && <pre className="crypto-result-text">{result.stdout.trim()}</pre>}
                    {result.stderr.trim() && <pre className="crypto-result-text crypto-result-stderr">{result.stderr.trim()}</pre>}
                </div>
            )}

            {/* Version conflicts */}
            {conflicts.size > 0 && (
                <div className="analyze-duplicates fade-in">
                    <h4>⚠️ Version Conflicts ({conflicts.size})</h4>
                    <div className="analyze-dup-list">
                        {[...conflicts.entries()].slice(0, 30).map(([name, versions], i) => (
                            <div key={i} className="analyze-dup-row">
                                <span className="analyze-dup-name">{name}</span>
                                <div className="analyze-dup-versions">
                                    {versions.map((v, j) => (
                                        <span key={j} className="analyze-dup-badge">{v}</span>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Tree visualization */}
            {mergedTree && (
                <div className="merge-tree fade-in">
                    <h4>🌳 Merged BOM Structure</h4>
                    {mergedTree.metadata?.component && (
                        <div className="merge-tree-root">
                            <ComponentNode component={mergedTree.metadata.component} depth={0} conflicts={conflicts} />
                        </div>
                    )}
                    <div className="merge-tree-children">
                        {(mergedTree.components || []).slice(0, 100).map((c, i) => (
                            <ComponentNode key={i} component={c} depth={0} conflicts={conflicts} />
                        ))}
                        {(mergedTree.components?.length || 0) > 100 && (
                            <div className="merge-tree-more">... and {(mergedTree.components?.length || 0) - 100} more</div>
                        )}
                    </div>
                </div>
            )}

            {inputFiles.length === 0 && (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🌳</span>
                    <h3>Hierarchical Merge Visualizer</h3>
                    <p>Select 2+ CycloneDX BOM files to merge flat or hierarchically, with version conflict detection</p>
                </div>
            )}
        </div>
    );
}

function ComponentNode({
    component, depth, conflicts,
}: {
    component: BomComponent; depth: number; conflicts: Map<string, string[]>;
}) {
    const [expanded, setExpanded] = useState(depth < 2);
    const key = component.group ? `${component.group}/${component.name}` : (component.name || "?");
    const hasConflict = conflicts.has(key);
    const hasChildren = component.components && component.components.length > 0;

    return (
        <div className="merge-node" style={{ marginLeft: depth * 16 }}>
            <div
                className={`merge-node-header ${hasConflict ? "merge-node-conflict" : ""}`}
                onClick={() => hasChildren && setExpanded(!expanded)}
            >
                {hasChildren && <span className="merge-node-toggle">{expanded ? "▼" : "▶"}</span>}
                <span className={`merge-node-type merge-type-${component.type || "library"}`}>
                    {component.type || "lib"}
                </span>
                <span className="merge-node-name">{key}</span>
                {component.version && (
                    <span className={`merge-node-ver ${hasConflict ? "merge-node-ver-warn" : ""}`}>
                        {component.version}
                    </span>
                )}
                {hasConflict && <span className="merge-node-conflict-badge">⚠️ conflict</span>}
            </div>
            {expanded && hasChildren && (
                <div className="merge-node-children">
                    {component.components!.map((c, i) => (
                        <ComponentNode key={i} component={c} depth={depth + 1} conflicts={conflicts} />
                    ))}
                </div>
            )}
        </div>
    );
}
