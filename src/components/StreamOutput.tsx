import { useEffect, useRef, useState } from "react";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

interface StreamLine {
    text: string;
    stream: "stdout" | "stderr";
    ts: number;
}

interface StreamOutputProps {
    runId: string | null;
    active: boolean;
}

export default function StreamOutput({ runId, active }: StreamOutputProps) {
    const [lines, setLines] = useState<StreamLine[]>([]);
    const [exitCode, setExitCode] = useState<number | null>(null);
    const [exitSuccess, setExitSuccess] = useState<boolean | null>(null);
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!runId || !active) return;

        // Reset on new run
        setLines([]);
        setExitCode(null);
        setExitSuccess(null);

        let unlistenStream: UnlistenFn | null = null;
        let unlistenExit: UnlistenFn | null = null;

        const setup = async () => {
            unlistenStream = await listen<{ line: string; stream: string }>(
                `cdx-stream-${runId}`,
                (event) => {
                    setLines((prev) => [
                        ...prev,
                        {
                            text: event.payload.line,
                            stream: event.payload.stream as "stdout" | "stderr",
                            ts: Date.now(),
                        },
                    ]);
                }
            );

            unlistenExit = await listen<{ code: number; success: boolean }>(
                `cdx-exit-${runId}`,
                (event) => {
                    setExitCode(event.payload.code);
                    setExitSuccess(event.payload.success);
                }
            );
        };

        setup();

        return () => {
            unlistenStream?.();
            unlistenExit?.();
        };
    }, [runId, active]);

    // Auto-scroll
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [lines]);

    if (!active && lines.length === 0) return null;

    return (
        <div className="stream-output">
            {/* Activity indicator */}
            <div className="stream-header">
                {exitCode === null ? (
                    <div className="stream-status running">
                        <div className="stream-progress-bar">
                            <div className="stream-progress-fill" />
                        </div>
                        <span>Streaming output…</span>
                    </div>
                ) : (
                    <div className={`stream-status ${exitSuccess ? "done" : "error"}`}>
                        <span className="status-dot" />
                        <span>
                            {exitSuccess ? "Completed" : "Failed"} — exit {exitCode}
                        </span>
                    </div>
                )}
                <span className="stream-line-count">{lines.length} lines</span>
            </div>

            {/* Stream content */}
            <div className="stream-content" ref={scrollRef}>
                {lines.map((l, i) => (
                    <div
                        key={i}
                        className={`stream-line ${l.stream === "stderr" ? "stream-line-err" : ""}`}
                    >
                        <span className="stream-line-num">{i + 1}</span>
                        <span className="stream-line-text">{l.text}</span>
                    </div>
                ))}
                {lines.length === 0 && exitCode === null && (
                    <div className="stream-waiting">Waiting for output…</div>
                )}
            </div>
        </div>
    );
}
