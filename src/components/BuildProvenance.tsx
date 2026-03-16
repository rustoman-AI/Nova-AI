import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── CI/CD detection ───────────────────────────────
const CI_PATTERNS: { pattern: RegExp; name: string; icon: string }[] = [
    { pattern: /jenkins/i, name: "Jenkins", icon: "🔧" },
    { pattern: /gitlab/i, name: "GitLab CI", icon: "🦊" },
    { pattern: /github.*action/i, name: "GitHub Actions", icon: "🐙" },
    { pattern: /circleci/i, name: "CircleCI", icon: "⚙️" },
    { pattern: /travis/i, name: "Travis CI", icon: "🏗️" },
    { pattern: /azure.*pipeline/i, name: "Azure Pipelines", icon: "☁️" },
    { pattern: /tekton/i, name: "Tekton", icon: "🚀" },
    { pattern: /argo/i, name: "Argo", icon: "🦑" },
    { pattern: /buildkite/i, name: "Buildkite", icon: "🪁" },
];

function detectCI(text: string): { name: string; icon: string } | null {
    for (const p of CI_PATTERNS) {
        if (p.pattern.test(text)) return { name: p.name, icon: p.icon };
    }
    return null;
}

// ─── Types ─────────────────────────────────────────
interface TaskStep {
    type?: string;
    name?: string;
    description?: string;
    commands?: { executed?: string; properties?: Record<string, string> }[];
    inputs?: { resource?: string; source?: { name?: string; url?: string } }[];
    outputs?: { resource?: string; type?: string }[];
    properties?: { name?: string; value?: string }[];
    timeStart?: string;
    timeEnd?: string;
}

interface Trigger {
    type?: string;
    event?: string;
    description?: string;
    resourceReferences?: { ref?: string }[];
}

interface Workspace {
    uid?: string;
    name?: string;
    description?: string;
    volume?: { mode?: string; path?: string; sizeAllocated?: string };
    accessMode?: string;
    mountPath?: string;
    aliases?: string[];
}

interface Workflow {
    "bom-ref"?: string;
    uid?: string;
    name?: string;
    description?: string;
    tasks?: TaskStep[];
    trigger?: Trigger;
    workspaces?: Workspace[];
    resourceReferences?: { ref?: string }[];
    properties?: { name?: string; value?: string }[];
}

interface Formula {
    "bom-ref"?: string;
    workflows?: Workflow[];
    components?: any[];
    services?: any[];
    properties?: { name?: string; value?: string }[];
}

// ─── Main Component ────────────────────────────────
export default function BuildProvenance() {
    const [formulas, setFormulas] = useState<Formula[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [expandedWf, setExpandedWf] = useState<Set<string>>(new Set());
    const [expandedTask, setExpandedTask] = useState<Set<string>>(new Set());

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select CycloneDX 1.5+ BOM",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setFormulas(bom.formulation || []);
        setLoaded(true);
        setExpandedWf(new Set());
        setExpandedTask(new Set());
    }, []);

    const toggleWf = useCallback((id: string) => {
        setExpandedWf(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
    }, []);
    const toggleTask = useCallback((id: string) => {
        setExpandedTask(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
    }, []);

    // Stats
    const stats = useMemo(() => {
        let workflows = 0, tasks = 0, inputs = 0, outputs = 0, pinned = 0, totalInputs = 0;
        let ciDetected: { name: string; icon: string } | null = null;
        for (const f of formulas) {
            for (const wf of f.workflows || []) {
                workflows++;
                const allText = JSON.stringify(wf);
                if (!ciDetected) ciDetected = detectCI(allText);
                for (const t of wf.tasks || []) {
                    tasks++;
                    for (const inp of t.inputs || []) {
                        totalInputs++;
                        inputs++;
                        if (inp.source?.url || inp.resource) pinned++;
                    }
                    outputs += (t.outputs || []).length;
                }
            }
        }
        const reproScore = totalInputs > 0 ? Math.round((pinned / totalInputs) * 100) : 0;
        return { formulas: formulas.length, workflows, tasks, inputs, outputs, reproScore, ciDetected };
    }, [formulas]);

    const hasData = formulas.length > 0;

    return (
        <div className="prov-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Build Provenance</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {hasData && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{stats.formulas} formulas</span>
                        <span className="depgraph-stat">{stats.workflows} workflows</span>
                        <span className="depgraph-stat">{stats.tasks} tasks</span>
                        <span className="depgraph-stat">{stats.inputs} inputs → {stats.outputs} outputs</span>
                        {stats.ciDetected && (
                            <span className="depgraph-stat" style={{ color: "#6366f1", borderColor: "#6366f1" }}>
                                {stats.ciDetected.icon} {stats.ciDetected.name}
                            </span>
                        )}
                    </div>
                )}
            </div>

            {hasData ? (
                <div className="prov-content fade-in">
                    {/* Reproducibility Score */}
                    <div className="analyze-stats">
                        <div className={`analyze-stat-card ${stats.reproScore >= 80 ? "" : "analyze-stat-warn"}`}>
                            <span className="analyze-stat-value" style={{
                                color: stats.reproScore >= 80 ? "#22c55e" : stats.reproScore >= 50 ? "#f59e0b" : "#ef4444"
                            }}>{stats.reproScore}%</span>
                            <span className="analyze-stat-label">Reproducibility ({stats.inputs} pinned inputs)</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.workflows}</span>
                            <span className="analyze-stat-label">Workflows</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.tasks}</span>
                            <span className="analyze-stat-label">Tasks</span>
                        </div>
                        {stats.ciDetected && (
                            <div className="analyze-stat-card">
                                <span className="analyze-stat-value">{stats.ciDetected.icon}</span>
                                <span className="analyze-stat-label">{stats.ciDetected.name}</span>
                            </div>
                        )}
                    </div>

                    {/* Formulas → Workflows → Tasks */}
                    {formulas.map((formula, fi) => (
                        <div key={fi} className="prov-formula">
                            <div className="prov-formula-header">
                                <span className="prov-formula-icon">📦</span>
                                <span className="prov-formula-title">Formula {formula["bom-ref"] || `#${fi + 1}`}</span>
                                {formula.components && <span className="prov-mini">{formula.components.length} components</span>}
                                {formula.services && <span className="prov-mini">{formula.services.length} services</span>}
                            </div>

                            {(formula.workflows || []).map((wf, wi) => {
                                const wfId = `${fi}-${wi}`;
                                const isExpanded = expandedWf.has(wfId);
                                return (
                                    <div key={wi} className="prov-workflow">
                                        <div className="prov-wf-header" onClick={() => toggleWf(wfId)}>
                                            <span className="merge-node-toggle">{isExpanded ? "▼" : "▶"}</span>
                                            <span className="prov-wf-icon">⚙️</span>
                                            <span className="prov-wf-name">{wf.name || wf.uid || `Workflow #${wi + 1}`}</span>
                                            {wf.trigger && (
                                                <span className="prov-trigger-badge">
                                                    ⚡ {wf.trigger.type || wf.trigger.event || "trigger"}
                                                </span>
                                            )}
                                            <span className="prov-mini">{(wf.tasks || []).length} tasks</span>
                                        </div>

                                        {isExpanded && (
                                            <div className="prov-wf-body">
                                                {wf.description && (
                                                    <div className="prov-wf-desc">{wf.description}</div>
                                                )}

                                                {/* Trigger details */}
                                                {wf.trigger && (
                                                    <div className="prov-trigger-card">
                                                        <b>Trigger:</b> {wf.trigger.type || "?"} — {wf.trigger.event || wf.trigger.description || ""}
                                                    </div>
                                                )}

                                                {/* Workspaces */}
                                                {wf.workspaces && wf.workspaces.length > 0 && (
                                                    <div className="prov-workspaces">
                                                        <b>Workspaces ({wf.workspaces.length}):</b>
                                                        {wf.workspaces.map((ws, wsi) => (
                                                            <div key={wsi} className="prov-ws-card">
                                                                <span className="prov-ws-name">📂 {ws.name || ws.uid || "?"}</span>
                                                                {ws.mountPath && <span className="prov-ws-path">{ws.mountPath}</span>}
                                                                {ws.volume?.path && <span className="prov-ws-path">vol: {ws.volume.path}</span>}
                                                                {ws.volume?.sizeAllocated && <span className="prov-mini">{ws.volume.sizeAllocated}</span>}
                                                                {ws.accessMode && <span className="prov-mini">{ws.accessMode}</span>}
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}

                                                {/* Task timeline */}
                                                <div className="prov-tasks">
                                                    {(wf.tasks || []).map((task, ti) => {
                                                        const taskId = `${wfId}-${ti}`;
                                                        const taskExpanded = expandedTask.has(taskId);
                                                        return (
                                                            <div key={ti} className="prov-task">
                                                                <div className="prov-task-header" onClick={() => toggleTask(taskId)}>
                                                                    <span className="prov-task-num">{ti + 1}</span>
                                                                    <span className="prov-task-name">{task.name || `Task #${ti + 1}`}</span>
                                                                    {task.type && <span className="prov-task-type">{task.type}</span>}
                                                                    {task.timeStart && (
                                                                        <span className="prov-mini">{task.timeStart.slice(0, 19)}</span>
                                                                    )}
                                                                    <span className="merge-node-toggle">{taskExpanded ? "▼" : "▶"}</span>
                                                                </div>

                                                                {taskExpanded && (
                                                                    <div className="prov-task-body">
                                                                        {task.description && <div className="prov-task-desc">{task.description}</div>}

                                                                        {/* Commands */}
                                                                        {task.commands && task.commands.length > 0 && (
                                                                            <div className="prov-commands">
                                                                                <b>Commands:</b>
                                                                                {task.commands.map((cmd, ci) => (
                                                                                    <code key={ci} className="prov-cmd">{cmd.executed || JSON.stringify(cmd.properties)}</code>
                                                                                ))}
                                                                            </div>
                                                                        )}

                                                                        {/* Inputs */}
                                                                        {task.inputs && task.inputs.length > 0 && (
                                                                            <div className="prov-io">
                                                                                <b>Inputs ({task.inputs.length}):</b>
                                                                                {task.inputs.map((inp, ii) => (
                                                                                    <div key={ii} className="prov-io-item">
                                                                                        <span className="prov-io-arrow">→</span>
                                                                                        {inp.source?.name && <span>{inp.source.name}</span>}
                                                                                        {inp.source?.url && <code className="prov-io-url">{inp.source.url}</code>}
                                                                                        {inp.resource && <code className="prov-io-url">{inp.resource}</code>}
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        )}

                                                                        {/* Outputs */}
                                                                        {task.outputs && task.outputs.length > 0 && (
                                                                            <div className="prov-io">
                                                                                <b>Outputs ({task.outputs.length}):</b>
                                                                                {task.outputs.map((out, oi) => (
                                                                                    <div key={oi} className="prov-io-item">
                                                                                        <span className="prov-io-arrow">←</span>
                                                                                        {out.resource && <code className="prov-io-url">{out.resource}</code>}
                                                                                        {out.type && <span className="prov-mini">{out.type}</span>}
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        )}

                                                                        {/* Time range */}
                                                                        {task.timeStart && task.timeEnd && (
                                                                            <div className="prov-time">
                                                                                ⏱️ {task.timeStart.slice(11, 19)} → {task.timeEnd.slice(11, 19)}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        );
                                                    })}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    ))}
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🏗️</span>
                    <h3>Build Provenance</h3>
                    <p>Open a CycloneDX 1.5+ BOM with <code>formulation[]</code> to view build pipeline provenance, tasks, workspaces, and reproducibility</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM does not contain formulation data</p>}
                </div>
            )}
        </div>
    );
}
