import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

interface DiffResult {
    added: DiffComponent[];
    removed: DiffComponent[];
    modified: DiffComponent[];
}

interface DiffComponent {
    name: string;
    version?: string;
    purl?: string;
    type?: string;
    changes?: { field: string; from: string; to: string }[];
}

export default function DiffViewer() {
    const [file1, setFile1] = useState<string | null>(null);
    const [file2, setFile2] = useState<string | null>(null);
    const [diff, setDiff] = useState<DiffResult | null>(null);
    const [rawOutput, setRawOutput] = useState<string>("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<"visual" | "raw">("visual");

    const pickFile = useCallback(async (which: 1 | 2) => {
        const file = await open({
            multiple: false,
            filters: [
                { name: "BOM Files", extensions: ["json", "xml"] },
                { name: "All Files", extensions: ["*"] },
            ],
        });
        if (file) {
            if (which === 1) setFile1(file as string);
            else setFile2(file as string);
        }
    }, []);

    const parseDiffOutput = useCallback((stdout: string): DiffResult => {
        try {
            const data = JSON.parse(stdout);
            // Try to parse as structured diff
            if (data.components) {
                const added: DiffComponent[] = [];
                const removed: DiffComponent[] = [];
                const modified: DiffComponent[] = [];

                for (const comp of (data.components.added || [])) {
                    added.push({ name: comp.name || comp["bom-ref"] || "unknown", version: comp.version, purl: comp.purl, type: comp.type });
                }
                for (const comp of (data.components.removed || [])) {
                    removed.push({ name: comp.name || comp["bom-ref"] || "unknown", version: comp.version, purl: comp.purl, type: comp.type });
                }
                for (const comp of (data.components.modified || [])) {
                    modified.push({
                        name: comp.name || comp["bom-ref"] || "unknown",
                        version: comp.version, purl: comp.purl, type: comp.type,
                        changes: comp.changes || [],
                    });
                }
                return { added, removed, modified };
            }
        } catch {
            // Fallback: parse line-by-line
        }

        // Fallback: return empty and show raw
        return { added: [], removed: [], modified: [] };
    }, []);

    const runDiff = useCallback(async () => {
        if (!file1 || !file2) return;
        setLoading(true);
        setError(null);
        setDiff(null);

        try {
            const res = await invoke<{ success: boolean; exit_code: number; stdout: string; stderr: string; tool: string }>(
                "diff_boms", { file1, file2 }
            );
            setRawOutput(res.stdout || res.stderr);
            if (res.stdout) {
                setDiff(parseDiffOutput(res.stdout));
            }
            if (!res.success) {
                setError(`Exit code ${res.exit_code}: ${res.stderr}`);
            }
        } catch (err: any) {
            setError(err?.toString?.() ?? String(err));
        }
        setLoading(false);
    }, [file1, file2, parseDiffOutput]);

    const totalChanges = diff ? diff.added.length + diff.removed.length + diff.modified.length : 0;

    return (
        <div className="diff-panel">
            {/* File pickers */}
            <div className="diff-config">
                <h2 className="diff-title">SBOM Diff Viewer</h2>
                <div className="diff-files-row">
                    <div className="diff-file-pick">
                        <label className="wizard-label">Base BOM</label>
                        <div className="diff-file-btn-row">
                            <button className="diff-pick-btn" onClick={() => pickFile(1)}>
                                📂 {file1 ? file1.split("/").pop() : "Select file..."}
                            </button>
                            {file1 && <button className="diff-clear-btn" onClick={() => setFile1(null)}>×</button>}
                        </div>
                    </div>
                    <div className="diff-arrow">→</div>
                    <div className="diff-file-pick">
                        <label className="wizard-label">Target BOM</label>
                        <div className="diff-file-btn-row">
                            <button className="diff-pick-btn" onClick={() => pickFile(2)}>
                                📂 {file2 ? file2.split("/").pop() : "Select file..."}
                            </button>
                            {file2 && <button className="diff-clear-btn" onClick={() => setFile2(null)}>×</button>}
                        </div>
                    </div>
                    <button
                        className="exec-btn diff-run-btn"
                        onClick={runDiff}
                        disabled={!file1 || !file2 || loading}
                    >
                        {loading ? <><span className="spinner" /> Diffing…</> : <>⚡ Run Diff</>}
                    </button>
                </div>
            </div>

            {error && <div className="json-error" style={{ margin: "0 24px" }}>{error}</div>}

            {/* Results */}
            {(diff || rawOutput) && (
                <div className="diff-results">
                    {/* Summary cards */}
                    {diff && (
                        <div className="diff-summary-cards">
                            <div className="diff-card diff-card-added">
                                <span className="diff-card-value">+{diff.added.length}</span>
                                <span className="diff-card-label">Added</span>
                            </div>
                            <div className="diff-card diff-card-removed">
                                <span className="diff-card-value">−{diff.removed.length}</span>
                                <span className="diff-card-label">Removed</span>
                            </div>
                            <div className="diff-card diff-card-modified">
                                <span className="diff-card-value">~{diff.modified.length}</span>
                                <span className="diff-card-label">Modified</span>
                            </div>
                            <div className="diff-card">
                                <span className="diff-card-value">{totalChanges}</span>
                                <span className="diff-card-label">Total Changes</span>
                            </div>
                        </div>
                    )}

                    {/* Tab switch */}
                    <div className="diff-tabs">
                        <button className={`output-tab ${activeTab === "visual" ? "active" : ""}`} onClick={() => setActiveTab("visual")}>
                            Visual Diff {totalChanges > 0 && <span className="tab-indicator">{totalChanges}</span>}
                        </button>
                        <button className={`output-tab ${activeTab === "raw" ? "active" : ""}`} onClick={() => setActiveTab("raw")}>
                            Raw Output
                        </button>
                    </div>

                    {activeTab === "visual" && diff ? (
                        <div className="diff-visual">
                            {/* Added */}
                            {diff.added.length > 0 && (
                                <div className="diff-section">
                                    <h4 className="diff-section-title diff-color-added">+ Added Components ({diff.added.length})</h4>
                                    {diff.added.map((c, i) => (
                                        <div key={i} className="diff-row diff-row-added">
                                            <span className="diff-comp-name">{c.name}</span>
                                            {c.version && <span className="diff-comp-ver">{c.version}</span>}
                                            {c.purl && <span className="diff-comp-purl">{c.purl}</span>}
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Removed */}
                            {diff.removed.length > 0 && (
                                <div className="diff-section">
                                    <h4 className="diff-section-title diff-color-removed">− Removed Components ({diff.removed.length})</h4>
                                    {diff.removed.map((c, i) => (
                                        <div key={i} className="diff-row diff-row-removed">
                                            <span className="diff-comp-name">{c.name}</span>
                                            {c.version && <span className="diff-comp-ver">{c.version}</span>}
                                            {c.purl && <span className="diff-comp-purl">{c.purl}</span>}
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Modified */}
                            {diff.modified.length > 0 && (
                                <div className="diff-section">
                                    <h4 className="diff-section-title diff-color-modified">~ Modified Components ({diff.modified.length})</h4>
                                    {diff.modified.map((c, i) => (
                                        <div key={i} className="diff-row diff-row-modified">
                                            <span className="diff-comp-name">{c.name}</span>
                                            {c.version && <span className="diff-comp-ver">{c.version}</span>}
                                            {c.changes && c.changes.length > 0 && (
                                                <div className="diff-changes">
                                                    {c.changes.map((ch, j) => (
                                                        <div key={j} className="diff-change">
                                                            <span className="diff-change-field">{ch.field}:</span>
                                                            <span className="diff-change-from">{ch.from}</span>
                                                            <span className="diff-change-arrow">→</span>
                                                            <span className="diff-change-to">{ch.to}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}

                            {totalChanges === 0 && (
                                <div className="diff-no-changes">No structural differences found. Check Raw Output for details.</div>
                            )}
                        </div>
                    ) : (
                        <div className="diff-raw">
                            <pre>{rawOutput || "No output"}</pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
