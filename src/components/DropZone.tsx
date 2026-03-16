import { useState, useEffect, ReactNode, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";

interface DropZoneProps {
    onFileDrop: (path: string) => void;
    accept?: string[];
    children?: ReactNode;
    className?: string;
}

interface DragDropPayload {
    paths: string[];
    position: { x: number; y: number };
}

export default function DropZone({
    onFileDrop,
    accept = [".json", ".xml", ".csv", ".cdx"],
    children,
    className = "",
}: DropZoneProps) {
    const [isDragging, setIsDragging] = useState(false);

    const matchesExt = useCallback(
        (path: string) => {
            if (accept.length === 0) return true;
            const ext = "." + path.split(".").pop()?.toLowerCase();
            return accept.includes(ext);
        },
        [accept]
    );

    useEffect(() => {
        const unsubs: Promise<() => void>[] = [];

        unsubs.push(
            listen<DragDropPayload>("tauri://drag-enter", () => {
                setIsDragging(true);
            })
        );

        unsubs.push(
            listen("tauri://drag-leave", () => {
                setIsDragging(false);
            })
        );

        unsubs.push(
            listen<DragDropPayload>("tauri://drag-drop", (event) => {
                setIsDragging(false);
                const paths = event.payload.paths;
                if (paths && paths.length > 0) {
                    const matched = paths.find(matchesExt);
                    if (matched) onFileDrop(matched);
                }
            })
        );

        return () => {
            unsubs.forEach((p) => p.then((f) => f()));
        };
    }, [onFileDrop, matchesExt]);

    return (
        <div className={`drop-zone ${isDragging ? "drop-zone-active" : ""} ${className}`}>
            {isDragging && (
                <div className="drop-zone-overlay">
                    <div className="drop-zone-message">
                        <span className="drop-zone-icon">📁</span>
                        <span>Drop your BOM file here</span>
                    </div>
                </div>
            )}
            {children}
        </div>
    );
}
