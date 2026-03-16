import { useEffect, useCallback } from "react";

interface KeyboardShortcuts {
    onExecute?: () => void;
    onClearOutput?: () => void;
    onFocusInput?: () => void;
    onHistoryUp?: () => void;
    onHistoryDown?: () => void;
    onOpenFile?: () => void;
    onCloseOverlay?: () => void;
    onSwitchTab?: (index: number) => void;
}

export default function useKeyboard(shortcuts: KeyboardShortcuts) {
    const handler = useCallback(
        (e: KeyboardEvent) => {
            const ctrl = e.ctrlKey || e.metaKey;
            const key = e.key.toLowerCase();

            // Ctrl+Enter — execute
            if (ctrl && e.key === "Enter") {
                e.preventDefault();
                shortcuts.onExecute?.();
                return;
            }

            // Ctrl+L — clear output
            if (ctrl && key === "l") {
                e.preventDefault();
                shortcuts.onClearOutput?.();
                return;
            }

            // Ctrl+K — focus input
            if (ctrl && key === "k") {
                e.preventDefault();
                shortcuts.onFocusInput?.();
                return;
            }

            // Ctrl+O — open file
            if (ctrl && key === "o") {
                e.preventDefault();
                shortcuts.onOpenFile?.();
                return;
            }

            // Escape — close overlay
            if (e.key === "Escape") {
                shortcuts.onCloseOverlay?.();
                return;
            }

            // Ctrl+1-5 — switch tabs
            if (ctrl && e.key >= "1" && e.key <= "5") {
                e.preventDefault();
                shortcuts.onSwitchTab?.(parseInt(e.key) - 1);
                return;
            }

            // Arrow up/down in input — history nav
            const active = document.activeElement;
            if (active && active.tagName === "INPUT" && active.classList.contains("cmd-input")) {
                if (e.key === "ArrowUp") {
                    e.preventDefault();
                    shortcuts.onHistoryUp?.();
                } else if (e.key === "ArrowDown") {
                    e.preventDefault();
                    shortcuts.onHistoryDown?.();
                }
            }
        },
        [shortcuts]
    );

    useEffect(() => {
        window.addEventListener("keydown", handler);
        return () => window.removeEventListener("keydown", handler);
    }, [handler]);
}
