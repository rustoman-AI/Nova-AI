import { useState, useMemo } from "react";

interface ExecResult {
    success: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    tool: string;
}

interface HistoryEntry {
    args: string;
    result: ExecResult;
    elapsed: number;
    timestamp: number;
}

interface HistoryDrawerProps {
    open: boolean;
    onClose: () => void;
    entries: HistoryEntry[];
    onRerun: (args: string) => void;
    onClear: () => void;
}

export type { HistoryEntry };

export default function HistoryDrawer({
    open,
    onClose,
    entries,
    onRerun,
    onClear,
}: HistoryDrawerProps) {
    const [search, setSearch] = useState("");
    const [filterStatus, setFilterStatus] = useState<"all" | "success" | "error">("all");

    const filtered = useMemo(() => {
        return entries.filter((e) => {
            if (filterStatus === "success" && !e.result.success) return false;
            if (filterStatus === "error" && e.result.success) return false;
            if (search && !e.args.toLowerCase().includes(search.toLowerCase())) return false;
            return true;
        });
    }, [entries, search, filterStatus]);

    const formatTime = (ts: number) => {
        const d = new Date(ts);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    };

    const copyToClipboard = async (text: string) => {
        try { await navigator.clipboard.writeText(`cyclonedx ${text}`); } catch { }
    };

    if (!open) return null;

    return (
        <>
            <div className="drawer-backdrop" onClick={onClose} />
            <div className="history-drawer drawer-enter">
                <div className="drawer-header">
                    <h3>Command History</h3>
                    <div className="drawer-header-actions">
                        <span className="drawer-count">{entries.length} commands</span>
                        <button className="drawer-clear-btn" onClick={onClear} title="Clear all">
                            🗑️
                        </button>
                        <button className="drawer-close-btn" onClick={onClose}>×</button>
                    </div>
                </div>

                {/* Filters */}
                <div className="drawer-filters">
                    <input
                        className="drawer-search"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search commands..."
                        autoFocus
                    />
                    <div className="drawer-filter-btns">
                        {(["all", "success", "error"] as const).map((s) => (
                            <button
                                key={s}
                                className={`drawer-filter-btn ${filterStatus === s ? "active" : ""}`}
                                onClick={() => setFilterStatus(s)}
                            >
                                {s === "all" ? "All" : s === "success" ? "✓ OK" : "✗ Fail"}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Entries */}
                <div className="drawer-entries">
                    {filtered.length === 0 ? (
                        <div className="drawer-empty">No matching commands</div>
                    ) : (
                        filtered.map((entry, i) => (
                            <div
                                key={`${entry.timestamp}-${i}`}
                                className={`drawer-entry ${entry.result.success ? "drawer-entry-ok" : "drawer-entry-err"}`}
                            >
                                <div className="drawer-entry-header">
                                    <span className={`drawer-status-dot ${entry.result.success ? "ok" : "err"}`} />
                                    <code className="drawer-entry-args">cyclonedx {entry.args}</code>
                                </div>
                                <div className="drawer-entry-meta">
                                    <span>{formatTime(entry.timestamp)}</span>
                                    <span>{entry.elapsed}ms</span>
                                    <span>exit {entry.result.exit_code}</span>
                                </div>
                                <div className="drawer-entry-actions">
                                    <button className="drawer-action-btn" onClick={() => onRerun(entry.args)} title="Re-run">
                                        ▶
                                    </button>
                                    <button className="drawer-action-btn" onClick={() => copyToClipboard(entry.args)} title="Copy">
                                        📋
                                    </button>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </>
    );
}
