import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

interface OrgInfo {
    name: string;
    url?: string;
    contacts: { name?: string; email?: string; phone?: string }[];
    source: string;
}

interface SupplierInfo {
    componentName: string;
    publisher?: string;
    supplier?: { name?: string; url?: string[] };
    manufacturer?: { name?: string; url?: string[] };
    author?: string;
    group?: string;
}

export default function SupplierIntelligence() {
    const [suppliers, setSuppliers] = useState<SupplierInfo[]>([]);
    const [orgs, setOrgs] = useState<OrgInfo[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [selectedOrg, setSelectedOrg] = useState<string | null>(null);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);

        const orgMap = new Map<string, OrgInfo>();

        // Metadata organization
        const metaOrg = bom.metadata?.component?.supplier || bom.metadata?.manufacture;
        if (metaOrg?.name) {
            orgMap.set(metaOrg.name, {
                name: metaOrg.name, url: metaOrg.url?.[0],
                contacts: metaOrg.contact || [], source: "metadata",
            });
        }

        // Component suppliers
        const suppList: SupplierInfo[] = [];
        for (const c of (bom.components || [])) {
            const name = c.group ? `${c.group}/${c.name}` : (c.name || "?");
            suppList.push({
                componentName: name, publisher: c.publisher,
                supplier: c.supplier, manufacturer: c.manufacturer,
                author: c.author, group: c.group,
            });

            if (c.supplier?.name) {
                if (!orgMap.has(c.supplier.name)) {
                    orgMap.set(c.supplier.name, {
                        name: c.supplier.name, url: c.supplier.url?.[0],
                        contacts: c.supplier.contact || [], source: "component-supplier",
                    });
                }
            }
            if (c.manufacturer?.name) {
                if (!orgMap.has(c.manufacturer.name)) {
                    orgMap.set(c.manufacturer.name, {
                        name: c.manufacturer.name, url: c.manufacturer.url?.[0],
                        contacts: c.manufacturer.contact || [], source: "component-manufacturer",
                    });
                }
            }
        }

        setSuppliers(suppList);
        setOrgs([...orgMap.values()]);
        setLoaded(true);
        setSelectedOrg(null);
    }, []);

    const stats = useMemo(() => {
        const hasPublisher = suppliers.filter(s => s.publisher).length;
        const hasSupplier = suppliers.filter(s => s.supplier?.name).length;
        const hasManufacturer = suppliers.filter(s => s.manufacturer?.name).length;
        const hasAuthor = suppliers.filter(s => s.author).length;
        const total = suppliers.length || 1;
        return {
            hasPublisher, hasSupplier, hasManufacturer, hasAuthor, total,
            pctPublisher: Math.round((hasPublisher / total) * 100),
            pctSupplier: Math.round((hasSupplier / total) * 100),
        };
    }, [suppliers]);

    const publisherCounts = useMemo(() => {
        const m = new Map<string, number>();
        for (const s of suppliers) {
            const pub = s.publisher || s.supplier?.name || s.manufacturer?.name || s.author || "(unknown)";
            m.set(pub, (m.get(pub) || 0) + 1);
        }
        return [...m].sort((a, b) => b[1] - a[1]).slice(0, 20);
    }, [suppliers]);

    const filteredSuppliers = useMemo(() => {
        if (!selectedOrg) return suppliers;
        return suppliers.filter(s =>
            s.publisher === selectedOrg || s.supplier?.name === selectedOrg ||
            s.manufacturer?.name === selectedOrg || s.author === selectedOrg
        );
    }, [suppliers, selectedOrg]);

    return (
        <div className="suppl-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">Supplier & Publisher Intelligence</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
            </div>

            {suppliers.length > 0 ? (
                <div className="suppl-content fade-in">
                    {/* Stats */}
                    <div className="analyze-stats">
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{orgs.length}</span>
                            <span className="analyze-stat-label">Organizations</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: stats.pctPublisher > 50 ? "#22c55e" : "#f59e0b" }}>{stats.pctPublisher}%</span>
                            <span className="analyze-stat-label">Has Publisher</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value" style={{ color: stats.pctSupplier > 50 ? "#22c55e" : "#f59e0b" }}>{stats.pctSupplier}%</span>
                            <span className="analyze-stat-label">Has Supplier</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.hasManufacturer}</span>
                            <span className="analyze-stat-label">Has Manufacturer</span>
                        </div>
                        <div className="analyze-stat-card">
                            <span className="analyze-stat-value">{stats.hasAuthor}</span>
                            <span className="analyze-stat-label">Has Author</span>
                        </div>
                    </div>

                    <div className="svc-list-and-detail">
                        {/* Org list + publisher counts */}
                        <div className="svc-list">
                            <div className="suppl-section-title">🏢 Top Publishers</div>
                            {publisherCounts.map(([name, cnt]) => {
                                const isActive = selectedOrg === name;
                                return (
                                    <div key={name}
                                        className={`svc-node-header ${isActive ? "svc-node-active" : ""}`}
                                        onClick={() => setSelectedOrg(selectedOrg === name ? null : name)}
                                    >
                                        <span className="svc-node-name">{name}</span>
                                        <span className="svc-mini-badge">{cnt}</span>
                                    </div>
                                );
                            })}
                        </div>

                        {/* Detail: components from selected org */}
                        <div className="svc-detail" style={{ flex: 1 }}>
                            {/* Org cards */}
                            {orgs.length > 0 && !selectedOrg && (
                                <div className="suppl-org-cards">
                                    {orgs.map((o, i) => (
                                        <div key={i} className="suppl-org-card" onClick={() => setSelectedOrg(o.name)}>
                                            <div className="suppl-org-name">🏢 {o.name}</div>
                                            {o.url && <div className="suppl-org-url">{o.url}</div>}
                                            {o.contacts.length > 0 && (
                                                <div className="suppl-org-contacts">
                                                    {o.contacts.map((c, j) => (
                                                        <span key={j} className="prov-mini">{c.name || c.email || "?"}</span>
                                                    ))}
                                                </div>
                                            )}
                                            <span className="prov-mini">{o.source}</span>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Filtered supplier table */}
                            {selectedOrg && (
                                <div>
                                    <h4 style={{ fontSize: "0.78rem", color: "var(--text-primary)", marginBottom: 6 }}>
                                        Components from "{selectedOrg}" ({filteredSuppliers.length})
                                    </h4>
                                    <div className="lic-table-wrap">
                                        <table className="lic-table">
                                            <thead><tr><th>Component</th><th>Publisher</th><th>Supplier</th><th>Author</th></tr></thead>
                                            <tbody>
                                                {filteredSuppliers.map((s, i) => (
                                                    <tr key={i}>
                                                        <td className="lic-id">{s.componentName}</td>
                                                        <td>{s.publisher || "—"}</td>
                                                        <td>{s.supplier?.name || "—"}</td>
                                                        <td>{s.author || "—"}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🏢</span>
                    <h3>Supplier & Publisher Intelligence</h3>
                    <p>Open a CycloneDX BOM to analyze suppliers, publishers, manufacturers, and organizational entities</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ No supplier data found</p>}
                </div>
            )}
        </div>
    );
}
