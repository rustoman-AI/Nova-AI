import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface PipelineRun {
    id: string;
    name: string;
    status: string;
    config: string | null;
    created_at: string;
    updated_at: string;
    step_count: number;
    steps_done: number;
}

interface PipelineStep {
    id: string;
    run_id: string;
    step_name: string;
    status: string;
    command: string | null;
    exit_code: number | null;
    stdout: string | null;
    stderr: string | null;
    started_at: string | null;
    finished_at: string | null;
}

interface PipelineArtifact {
    id: string;
    run_id: string;
    step_id: string | null;
    file_path: string;
    file_type: string | null;
    created_at: string;
}

interface PipelineRunDetail {
    run: PipelineRun;
    steps: PipelineStep[];
    artifacts: PipelineArtifact[];
}

const STATUS_ICONS: Record<string, string> = {
    done: "✅", failed: "❌", running: "⏳", pending: "⬜", skipped: "⏭️",
};

const STATUS_CLASSES: Record<string, string> = {
    done: "pipe-status-done", failed: "pipe-status-failed",
    running: "pipe-status-running", pending: "pipe-status-pending",
};

function formatTs(ts: string): string {
    const num = parseInt(ts, 10);
    if (isNaN(num)) return ts;
    return new Date(num * 1000).toLocaleString("ru-RU", {
        day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
    });
}

export default function PipelineHistory() {
    const [runs, setRuns] = useState<PipelineRun[]>([]);
    const [detail, setDetail] = useState<PipelineRunDetail | null>(null);

    const loadRuns = useCallback(async () => {
        try {
            const list = await invoke<PipelineRun[]>("pipeline_list");
            setRuns(list);
        } catch (e) {
            console.error("pipeline_list error:", e);
        }
    }, []);

    useEffect(() => { loadRuns(); }, [loadRuns]);

    const openDetail = useCallback(async (runId: string) => {
        if (detail?.run.id === runId) { setDetail(null); return; }
        try {
            const d = await invoke<PipelineRunDetail>("pipeline_get", { runId });
            setDetail(d);
        } catch (e) {
            console.error("pipeline_get error:", e);
        }
    }, [detail]);

    const deleteRun = useCallback(async (runId: string) => {
        try {
            await invoke("pipeline_delete", { runId });
            if (detail?.run.id === runId) setDetail(null);
            await loadRuns();
        } catch (e) {
            console.error("pipeline_delete error:", e);
        }
    }, [detail, loadRuns]);

    return (
        <div className="pipe-panel">
            <div className="pipe-header">
                <h2 className="pipe-title">Pipeline Runs</h2>
                <button className="preset-btn" onClick={loadRuns}>🔄 Refresh</button>
            </div>

            {runs.length === 0 ? (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📊</span>
                    <h3>No pipeline runs yet</h3>
                    <p>Run the NIST wizard to create your first pipeline</p>
                </div>
            ) : (
                <div className="pipe-list">
                    {runs.map((run) => {
                        const isOpen = detail?.run.id === run.id;
                        const pct = run.step_count > 0 ? Math.round((run.steps_done / run.step_count) * 100) : 0;
                        let config: any = {};
                        try { if (run.config) config = JSON.parse(run.config); } catch { }

                        return (
                            <div key={run.id} className={`pipe-run ${isOpen ? "pipe-run-open" : ""}`}>
                                <div className="pipe-run-header" onClick={() => openDetail(run.id)}>
                                    <span className={`pipe-run-status ${STATUS_CLASSES[run.status] || ""}`}>
                                        {STATUS_ICONS[run.status] || "?"}
                                    </span>
                                    <div className="pipe-run-info">
                                        <span className="pipe-run-name">{run.name}</span>
                                        <span className="pipe-run-meta">
                                            {formatTs(run.created_at)} · {run.steps_done}/{run.step_count} steps
                                        </span>
                                    </div>
                                    <div className="pipe-run-progress-bar">
                                        <div className="pipe-run-progress-fill" style={{ width: `${pct}%` }} />
                                    </div>
                                    <button
                                        className="drawer-clear-btn"
                                        onClick={(e) => { e.stopPropagation(); deleteRun(run.id); }}
                                        title="Delete"
                                    >
                                        🗑
                                    </button>
                                    <span className="pipe-run-arrow">{isOpen ? "▼" : "▶"}</span>
                                </div>

                                {isOpen && detail && (
                                    <div className="pipe-detail fade-in">
                                        {/* Config */}
                                        {config.appName && (
                                            <div className="pipe-config">
                                                <span className="pipe-config-item">📦 {config.appName} {config.appVersion}</span>
                                                {config.manufacturer && <span className="pipe-config-item">🏢 {config.manufacturer}</span>}
                                                {config.projectDir && <span className="pipe-config-item">📁 {config.projectDir}</span>}
                                            </div>
                                        )}

                                        {/* Steps timeline */}
                                        <div className="pipe-steps">
                                            {detail.steps.map((step) => (
                                                <StepRow key={step.id} step={step} />
                                            ))}
                                        </div>

                                        {/* Artifacts */}
                                        {detail.artifacts.length > 0 && (
                                            <div className="pipe-artifacts">
                                                <h5>📁 Artifacts</h5>
                                                {detail.artifacts.map((a) => (
                                                    <div key={a.id} className="pipe-artifact-row">
                                                        <span className="pipe-artifact-type">{a.file_type || "file"}</span>
                                                        <span className="pipe-artifact-path">{a.file_path}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

function StepRow({ step }: { step: PipelineStep }) {
    const [expanded, setExpanded] = useState(false);
    return (
        <div className={`pipe-step ${STATUS_CLASSES[step.status] || ""}`}>
            <div className="pipe-step-header" onClick={() => setExpanded(!expanded)}>
                <span className="pipe-step-icon">{STATUS_ICONS[step.status] || "?"}</span>
                <span className="pipe-step-name">{step.step_name}</span>
                {step.exit_code !== null && (
                    <span className={`pipe-step-exit ${step.exit_code === 0 ? "" : "pipe-step-exit-err"}`}>
                        exit {step.exit_code}
                    </span>
                )}
                {step.command && <span className="pipe-step-cmd">{step.command.slice(0, 60)}</span>}
                <span className="pipe-step-arrow">{expanded ? "▼" : "▶"}</span>
            </div>
            {expanded && (step.stdout || step.stderr) && (
                <div className="pipe-step-output fade-in">
                    {step.stdout && (
                        <div className="pipe-step-stdout">
                            <strong>stdout:</strong>
                            <pre>{step.stdout.slice(0, 2000)}</pre>
                        </div>
                    )}
                    {step.stderr && (
                        <div className="pipe-step-stderr">
                            <strong>stderr:</strong>
                            <pre>{step.stderr.slice(0, 2000)}</pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
