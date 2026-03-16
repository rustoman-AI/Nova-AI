import { useState, useCallback, createContext, useContext, ReactNode } from "react";

interface Toast {
    id: number;
    type: "success" | "error" | "info";
    title: string;
    message?: string;
    ts: number;
}

interface ToastContextValue {
    toasts: Toast[];
    addToast: (type: Toast["type"], title: string, message?: string) => void;
    removeToast: (id: number) => void;
}

const ToastContext = createContext<ToastContextValue>({
    toasts: [],
    addToast: () => { },
    removeToast: () => { },
});

export function useToast() {
    return useContext(ToastContext);
}

let toastId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
    const [toasts, setToasts] = useState<Toast[]>([]);

    const addToast = useCallback((type: Toast["type"], title: string, message?: string) => {
        const id = ++toastId;
        const toast: Toast = { id, type, title, message, ts: Date.now() };
        setToasts((prev) => [...prev, toast]);

        // Auto-dismiss after 4s
        setTimeout(() => {
            setToasts((prev) => prev.filter((t) => t.id !== id));
        }, 4000);
    }, []);

    const removeToast = useCallback((id: number) => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
    }, []);

    return (
        <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
            {children}
            <div className="toast-stack">
                {toasts.map((t) => (
                    <div key={t.id} className={`toast toast-${t.type} toast-enter`}>
                        <div className="toast-icon">
                            {t.type === "success" ? "✓" : t.type === "error" ? "✗" : "ℹ"}
                        </div>
                        <div className="toast-body">
                            <span className="toast-title">{t.title}</span>
                            {t.message && <span className="toast-msg">{t.message}</span>}
                        </div>
                        <button className="toast-close" onClick={() => removeToast(t.id)}>×</button>
                    </div>
                ))}
            </div>
        </ToastContext.Provider>
    );
}
