import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Types ─────────────────────────────────────────
interface ServiceData {
    flow?: string;
    classification?: string;
    name?: string;
    description?: string;
}

interface BomService {
    "bom-ref"?: string;
    name?: string;
    group?: string;
    version?: string;
    description?: string;
    endpoints?: string[];
    authenticated?: boolean;
    "x-trust-boundary"?: boolean;
    trustZone?: string;
    data?: ServiceData[];
    services?: BomService[];
    provider?: { name?: string; url?: string[] };
    externalReferences?: { url?: string; type?: string }[];
}

// ─── Data classification colors ────────────────────
const CLASS_COLORS: Record<string, string> = {
    public: "#22c55e",
    internal: "#3b82f6",
    confidential: "#f59e0b",
    restricted: "#ef4444",
    sensitive: "#dc2626",
    pii: "#ec4899",
};

// ─── Main Component ────────────────────────────────
export default function ServicesPanel() {
    const [services, setServices] = useState<BomService[]>([]);
    const [selected, setSelected] = useState<BomService | null>(null);
    const [loaded, setLoaded] = useState(false);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM file",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        setServices(bom.services || []);
        setLoaded(true);
        setSelected(null);
    }, []);

    // Flatten nested services for stats
    const allServices = useMemo(() => {
        const result: BomService[] = [];
        function walk(svcs: BomService[]) {
            for (const s of svcs) {
                result.push(s);
                if (s.services) walk(s.services);
            }
        }
        walk(services);
        return result;
    }, [services]);

    const stats = useMemo(() => {
        const boundary = allServices.filter(s => s["x-trust-boundary"] || s.trustZone).length;
        const authenticated = allServices.filter(s => s.authenticated).length;
        const withData = allServices.filter(s => s.data && s.data.length > 0).length;
        return { total: allServices.length, boundary, authenticated, withData };
    }, [allServices]);

    return (
        <div className="svc-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Services Inventory</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {allServices.length > 0 && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{stats.total} services</span>
                        {stats.boundary > 0 && <span className="depgraph-stat depgraph-stat-warn">🛡️ {stats.boundary} trust boundary</span>}
                        <span className="depgraph-stat">{stats.authenticated} authenticated</span>
                        <span className="depgraph-stat">{stats.withData} with data flows</span>
                    </div>
                )}
            </div>

            {allServices.length > 0 ? (
                <div className="svc-content fade-in">
                    <div className="svc-list-and-detail">
                        {/* Services list */}
                        <div className="svc-list">
                            {services.map((s, i) => (
                                <ServiceNode key={i} service={s} depth={0} selected={selected} onSelect={setSelected} />
                            ))}
                        </div>

                        {/* Detail panel */}
                        {selected && (
                            <div className="svc-detail fade-in">
                                <div className="svc-detail-header">
                                    <h3>{selected.group ? `${selected.group}/` : ""}{selected.name || "?"}</h3>
                                    <button className="merge-file-rm" onClick={() => setSelected(null)}>✕</button>
                                </div>

                                {selected.version && <div className="svc-detail-row"><b>Version:</b> {selected.version}</div>}
                                {selected.description && <div className="svc-detail-row">{selected.description}</div>}

                                {/* Auth & Trust */}
                                <div className="svc-badges">
                                    {selected.authenticated !== undefined && (
                                        <span className={`svc-auth-badge ${selected.authenticated ? "svc-auth-yes" : "svc-auth-no"}`}>
                                            {selected.authenticated ? "🔐 Authenticated" : "🔓 Unauthenticated"}
                                        </span>
                                    )}
                                    {(selected["x-trust-boundary"] || selected.trustZone) && (
                                        <span className="svc-trust-badge">
                                            🛡️ Trust Boundary {selected.trustZone ? `(${selected.trustZone})` : ""}
                                        </span>
                                    )}
                                </div>

                                {/* Endpoints */}
                                {selected.endpoints && selected.endpoints.length > 0 && (
                                    <div className="svc-endpoints">
                                        <b>Endpoints ({selected.endpoints.length}):</b>
                                        {selected.endpoints.map((ep, j) => (
                                            <div key={j} className="svc-endpoint">{ep}</div>
                                        ))}
                                    </div>
                                )}

                                {/* Data flows */}
                                {selected.data && selected.data.length > 0 && (
                                    <div className="svc-data-flows">
                                        <b>Data Flows ({selected.data.length}):</b>
                                        {selected.data.map((d, j) => (
                                            <div key={j} className="svc-data-card">
                                                <span className="svc-data-flow">{d.flow || "—"}</span>
                                                {d.classification && (
                                                    <span className="svc-class-badge" style={{
                                                        color: CLASS_COLORS[d.classification.toLowerCase()] || "#64748b",
                                                        borderColor: CLASS_COLORS[d.classification.toLowerCase()] || "#64748b",
                                                    }}>
                                                        {d.classification}
                                                    </span>
                                                )}
                                                {d.name && <span className="svc-data-name">{d.name}</span>}
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* Provider */}
                                {selected.provider?.name && (
                                    <div className="svc-detail-row"><b>Provider:</b> {selected.provider.name}</div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📋</span>
                    <h3>Services Inventory</h3>
                    <p>Open a CycloneDX BOM with <code>services[]</code> to view API services, endpoints, data flows, and trust boundaries</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ This BOM does not contain services data</p>}
                </div>
            )}
        </div>
    );
}

// ─── Recursive Service Node ────────────────────────
function ServiceNode({ service, depth, selected, onSelect }: {
    service: BomService; depth: number; selected: BomService | null; onSelect: (s: BomService) => void;
}) {
    const [expanded, setExpanded] = useState(depth < 2);
    const hasChildren = service.services && service.services.length > 0;
    const isActive = selected?.["bom-ref"] === service["bom-ref"] && selected?.name === service.name;
    const endpointCount = service.endpoints?.length || 0;
    const dataFlows = service.data?.length || 0;

    return (
        <div className="svc-node" style={{ marginLeft: depth * 14 }}>
            <div className={`svc-node-header ${isActive ? "svc-node-active" : ""}`} onClick={() => onSelect(service)}>
                {hasChildren && (
                    <span className="merge-node-toggle" onClick={e => { e.stopPropagation(); setExpanded(!expanded); }}>
                        {expanded ? "▼" : "▶"}
                    </span>
                )}
                <span className="svc-node-name">{service.name || "?"}</span>
                {service.version && <span className="svc-node-ver">{service.version}</span>}
                {service.authenticated && <span className="svc-mini-badge svc-mini-auth">🔐</span>}
                {(service["x-trust-boundary"] || service.trustZone) && <span className="svc-mini-badge svc-mini-trust">🛡️</span>}
                {endpointCount > 0 && <span className="svc-mini-badge">{endpointCount} ep</span>}
                {dataFlows > 0 && <span className="svc-mini-badge svc-mini-data">{dataFlows} data</span>}
            </div>
            {expanded && hasChildren && (
                <div className="svc-node-children">
                    {service.services!.map((child, i) => (
                        <ServiceNode key={i} service={child} depth={depth + 1} selected={selected} onSelect={onSelect} />
                    ))}
                </div>
            )}
        </div>
    );
}
