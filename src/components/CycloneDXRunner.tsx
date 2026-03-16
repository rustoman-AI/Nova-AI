import { useState, useCallback, useEffect } from "react";
import { type HistoryEntry } from "./HistoryDrawer";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import DropZone from "./DropZone";
import StreamOutput from "./StreamOutput";

interface ExecResult {
    success: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    tool: string;
}

const PRESETS = [
    { label: "--help", args: "--help" },
    { label: "validate", args: "validate --help" },
    { label: "convert", args: "convert --help" },
    { label: "merge", args: "merge --help" },
    { label: "diff", args: "diff --help" },
    { label: "analyze", args: "analyze --help" },
    { label: "add files", args: "add files --help" },
    { label: "sign", args: "sign --help" },
    { label: "verify", args: "verify --help" },
    { label: "keygen", args: "keygen --help" },
];

let runCounter = 0;

interface RunnerProps {
    onHistoryAdd?: (entry: HistoryEntry) => void;
}

export default function CycloneDXRunner({ onHistoryAdd }: RunnerProps) {
    const [args, setArgs] = useState("--help");
    const [result, setResult] = useState<ExecResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState<"stdout" | "stderr">("stdout");
    const [elapsed, setElapsed] = useState<number | null>(null);
    // Listen for rerun events from HistoryDrawer
    useEffect(() => {
        const handler = (e: Event) => {
            const args = (e as CustomEvent).detail;
            if (typeof args === "string") setArgs(args);
        };
        window.addEventListener("cdx-rerun", handler);
        return () => window.removeEventListener("cdx-rerun", handler);
    }, []);

    // Streaming
    const [streaming, setStreaming] = useState(false);
    const [streamRunId, setStreamRunId] = useState<string | null>(null);
    const [streamActive, setStreamActive] = useState(false);

    // File picker: insert path into args
    const pickFile = useCallback(async (purpose: "input" | "output") => {
        const file = await open({
            multiple: false,
            filters: [
                { name: "BOM Files", extensions: ["json", "xml", "csv", "cdx"] },
                { name: "All Files", extensions: ["*"] },
            ],
        });
        if (file) {
            const flag = purpose === "input" ? "--input-file" : "--output-file";
            setArgs((prev) => {
                // Replace existing flag or append
                const parts = prev.split(" ");
                const idx = parts.indexOf(flag);
                if (idx !== -1 && idx + 1 < parts.length) {
                    parts[idx + 1] = file as string;
                    return parts.join(" ");
                }
                return `${prev} ${flag} ${file}`;
            });
        }
    }, []);

    // Handle file drop
    const handleFileDrop = useCallback((path: string) => {
        const ext = path.split(".").pop()?.toLowerCase() || "json";
        const format = ext === "xml" ? "xml" : "json";
        setArgs(`validate --input-file ${path} --input-format ${format}`);
    }, []);

    // Execute (simple mode)
    const runSimple = useCallback(async () => {
        if (loading) return;
        setLoading(true);
        setResult(null);
        setElapsed(null);

        const t0 = performance.now();
        try {
            const res = await invoke<ExecResult>("run_cyclonedx", {
                args: args.split(" ").filter(Boolean),
            });
            const dt = Math.round(performance.now() - t0);
            setResult(res);
            setElapsed(dt);
            setActiveTab(res.stderr && !res.stdout ? "stderr" : "stdout");
            onHistoryAdd?.({ args, result: res, elapsed: dt, timestamp: Date.now() });
        } catch (err: any) {
            const dt = Math.round(performance.now() - t0);
            const errResult: ExecResult = {
                success: false,
                exit_code: -1,
                stdout: "",
                stderr: err?.toString?.() ?? String(err),
                tool: "cyclonedx",
            };
            setResult(errResult);
            setElapsed(dt);
            setActiveTab("stderr");
        }
        setLoading(false);
    }, [args, loading]);

    // Execute (streaming mode)
    const runStreaming = useCallback(async () => {
        if (loading) return;
        setLoading(true);
        setResult(null);
        setElapsed(null);

        const id = `run-${++runCounter}-${Date.now()}`;
        setStreamRunId(id);
        setStreamActive(true);

        try {
            await invoke("run_cyclonedx_streaming", {
                args: args.split(" ").filter(Boolean),
                runId: id,
            });
        } catch (err: any) {
            console.error("Streaming error:", err);
        }
        setStreamActive(false);
        setLoading(false);
    }, [args, loading]);

    const run = streaming ? runStreaming : runSimple;

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            run();
        }
    };

    const stdoutLines = result?.stdout?.split("\n").length ?? 0;
    const stderrLines = result?.stderr?.split("\n").length ?? 0;

    return (
        <DropZone onFileDrop={handleFileDrop} className="runner-drop-zone">
            <div className="runner-panel">
                {/* Header */}
                <header className="header">
                    <div className="header-row">
                        <div className="header-title">
                            <span className="header-logo">🛡️</span>
                            <h1>CycloneDX CLI</h1>
                            <span className="header-badge">v0.30.0</span>
                        </div>
                        <div className="header-right">
                            <label className="stream-toggle" title="Enable streaming output (real-time)">
                                <input
                                    type="checkbox"
                                    checked={streaming}
                                    onChange={(e) => setStreaming(e.target.checked)}
                                />
                                <span className="stream-toggle-slider" />
                                <span className="stream-toggle-label">Stream</span>
                            </label>
                        </div>
                    </div>

                    {/* Presets */}
                    <div className="presets-row">
                        {PRESETS.map((p) => (
                            <button
                                key={p.label}
                                className={`preset-btn ${args === p.args ? "active" : ""}`}
                                onClick={() => setArgs(p.args)}
                            >
                                {p.label}
                            </button>
                        ))}
                    </div>
                </header>

                {/* Input */}
                <div className="input-area">
                    <div className="input-row">
                        <span className="cmd-prefix">cyclonedx</span>
                        <input
                            className="cmd-input"
                            value={args}
                            onChange={(e) => setArgs(e.target.value)}
                            onKeyDown={handleKeyDown}
                            placeholder="validate --input-file bom.json --input-format json"
                            disabled={loading}
                            autoFocus
                        />
                        <button
                            className="file-pick-btn"
                            onClick={() => pickFile("input")}
                            title="Pick input file"
                            disabled={loading}
                        >
                            📂
                        </button>
                        <button
                            className="file-pick-btn"
                            onClick={() => pickFile("output")}
                            title="Pick output file"
                            disabled={loading}
                        >
                            💾
                        </button>
                        <button className="exec-btn" onClick={run} disabled={loading}>
                            {loading ? (
                                <>
                                    <span className="spinner" />
                                    Running…
                                </>
                            ) : (
                                <>▶ Execute</>
                            )}
                        </button>
                    </div>
                </div>

                {/* Output */}
                <div className="output-area">
                    {streaming && streamRunId ? (
                        <StreamOutput runId={streamRunId} active={streamActive} />
                    ) : !result && !loading ? (
                        <div className="output-empty">
                            <span className="output-empty-icon">⚡</span>
                            <p>
                                Enter a command and click <strong>Execute</strong> or press{" "}
                                <strong>Enter</strong>.
                                <br />
                                Drag & drop a BOM file to auto-validate.
                            </p>
                        </div>
                    ) : loading && !result ? (
                        <div className="output-empty loading-pulse">
                            <span className="output-empty-icon">⏳</span>
                            <p>Running cyclonedx…</p>
                        </div>
                    ) : result ? (
                        <div className="fade-in" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
                            <div className="status-bar">
                                <span className={`status-badge ${result.success ? "success" : "error"}`}>
                                    <span className="status-dot" />
                                    {result.success ? "SUCCESS" : "FAIL"} — exit {result.exit_code}
                                </span>
                                {elapsed !== null && (
                                    <span className="status-meta">{elapsed}ms</span>
                                )}
                            </div>
                            <div className="output-panel">
                                <div className="output-tabs">
                                    <button
                                        className={`output-tab ${activeTab === "stdout" ? "active" : ""}`}
                                        onClick={() => setActiveTab("stdout")}
                                    >
                                        stdout
                                        {stdoutLines > 1 && <span className="tab-indicator">{stdoutLines}</span>}
                                    </button>
                                    <button
                                        className={`output-tab ${activeTab === "stderr" ? "active" : ""}`}
                                        onClick={() => setActiveTab("stderr")}
                                    >
                                        stderr
                                        {stderrLines > 1 && <span className="tab-indicator">{stderrLines}</span>}
                                    </button>
                                </div>
                                <div className="output-content">
                                    {activeTab === "stdout" ? (
                                        result.stdout ? <pre>{result.stdout}</pre> : <span className="output-empty-inline">No stdout output</span>
                                    ) : result.stderr ? (
                                        <pre>{result.stderr}</pre>
                                    ) : (
                                        <span className="output-empty-inline">No stderr output</span>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : null}
                </div>
            </div>
        </DropZone>
    );
}
