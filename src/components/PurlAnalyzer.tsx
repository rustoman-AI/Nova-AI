import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

interface PurlInfo {
    raw: string;
    type: string;
    namespace: string;
    name: string;
    version: string;
    qualifiers: Record<string, string>;
    subpath: string;
    componentName: string;
}

function parsePurl(raw: string): Omit<PurlInfo, "componentName"> {
    // pkg:type/namespace/name@version?qualifiers#subpath
    const result: Omit<PurlInfo, "componentName"> = { raw, type: "", namespace: "", name: "", version: "", qualifiers: {}, subpath: "" };
    let s = raw;
    if (s.startsWith("pkg:")) s = s.slice(4);
    // subpath
    const hashIdx = s.indexOf("#");
    if (hashIdx !== -1) { result.subpath = s.slice(hashIdx + 1); s = s.slice(0, hashIdx); }
    // qualifiers
    const qIdx = s.indexOf("?");
    if (qIdx !== -1) {
        const qs = s.slice(qIdx + 1);
        s = s.slice(0, qIdx);
        for (const pair of qs.split("&")) {
            const [k, v] = pair.split("=");
            if (k) result.qualifiers[decodeURIComponent(k)] = decodeURIComponent(v || "");
        }
    }
    // version
    const atIdx = s.indexOf("@");
    if (atIdx !== -1) { result.version = decodeURIComponent(s.slice(atIdx + 1)); s = s.slice(0, atIdx); }
    // type
    const slashIdx = s.indexOf("/");
    if (slashIdx !== -1) {
        result.type = s.slice(0, slashIdx);
        s = s.slice(slashIdx + 1);
    }
    // namespace/name
    const lastSlash = s.lastIndexOf("/");
    if (lastSlash !== -1) {
        result.namespace = decodeURIComponent(s.slice(0, lastSlash));
        result.name = decodeURIComponent(s.slice(lastSlash + 1));
    } else {
        result.name = decodeURIComponent(s);
    }
    return result;
}

const TYPE_COLORS: Record<string, string> = {
    maven: "#e76f00", npm: "#cb3837", pypi: "#3776ab", golang: "#00add8",
    nuget: "#6d429c", cargo: "#dea584", gem: "#cc342d", cocoapods: "#8b7e6a",
    composer: "#f28d1a", swift: "#fa7343", pub: "#02569b", hex: "#6e4a7e",
    generic: "#64748b",
};

export default function PurlAnalyzer() {
    const [purls, setPurls] = useState<PurlInfo[]>([]);
    const [loaded, setLoaded] = useState(false);
    const [filterType, setFilterType] = useState<string | null>(null);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select BOM",
        });
        if (!f) return;
        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        const result: PurlInfo[] = [];
        for (const c of (bom.components || [])) {
            if (!c.purl) continue;
            const parsed = parsePurl(c.purl);
            const cname = c.group ? `${c.group}/${c.name}` : (c.name || "?");
            result.push({ ...parsed, componentName: cname });
        }
        setPurls(result);
        setLoaded(true);
    }, []);

    const typeCounts = useMemo(() => {
        const m = new Map<string, number>();
        for (const p of purls) m.set(p.type, (m.get(p.type) || 0) + 1);
        return [...m].sort((a, b) => b[1] - a[1]);
    }, [purls]);

    const nsCounts = useMemo(() => {
        const m = new Map<string, number>();
        for (const p of purls) if (p.namespace) m.set(p.namespace, (m.get(p.namespace) || 0) + 1);
        return [...m].sort((a, b) => b[1] - a[1]).slice(0, 15);
    }, [purls]);

    const qualStats = useMemo(() => {
        const m = new Map<string, number>();
        for (const p of purls) for (const k of Object.keys(p.qualifiers)) m.set(k, (m.get(k) || 0) + 1);
        return [...m].sort((a, b) => b[1] - a[1]);
    }, [purls]);


    const filtered = useMemo(() => {
        if (!filterType) return purls;
        return purls.filter(p => p.type === filterType);
    }, [purls, filterType]);

    return (
        <div className="purl-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">PURL Analyzer</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {purls.length > 0 && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{purls.length} PURLs</span>
                        <span className="depgraph-stat">{typeCounts.length} types</span>
                        <span className="depgraph-stat">{nsCounts.length} namespaces</span>
                    </div>
                )}
            </div>

            {purls.length > 0 ? (
                <div className="purl-content fade-in">
                    {/* Type breakdown */}
                    <div className="purl-types">
                        {typeCounts.map(([type, cnt]) => {
                            const pct = Math.round((cnt / purls.length) * 100);
                            const color = TYPE_COLORS[type] || "#64748b";
                            const isActive = filterType === type;
                            return (
                                <div key={type} className={`purl-type-card ${isActive ? "purl-type-active" : ""}`}
                                    onClick={() => setFilterType(filterType === type ? null : type)}
                                    style={{ borderColor: isActive ? color : undefined }}>
                                    <span className="purl-type-name" style={{ color }}>{type}</span>
                                    <span className="purl-type-count">{cnt}</span>
                                    <span className="purl-type-pct">{pct}%</span>
                                </div>
                            );
                        })}
                    </div>

                    {/* Namespace top-15 + qualifier stats side by side */}
                    <div className="purl-stats-row">
                        {nsCounts.length > 0 && (
                            <div className="purl-stat-box">
                                <h4>📦 Top Namespaces</h4>
                                {nsCounts.map(([ns, cnt]) => (
                                    <div key={ns} className="purl-ns-row">
                                        <span className="purl-ns-name">{ns}</span>
                                        <span className="purl-ns-count">{cnt}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                        {qualStats.length > 0 && (
                            <div className="purl-stat-box">
                                <h4>🔧 Qualifiers</h4>
                                {qualStats.map(([q, cnt]) => (
                                    <div key={q} className="purl-ns-row">
                                        <span className="purl-ns-name">{q}</span>
                                        <span className="purl-ns-count">{cnt}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Table */}
                    <div className="lic-table-wrap" style={{ flex: 1, overflow: "auto" }}>
                        <table className="lic-table">
                            <thead><tr><th>Type</th><th>Namespace</th><th>Name</th><th>Version</th><th>Qualifiers</th></tr></thead>
                            <tbody>
                                {filtered.slice(0, 200).map((p, i) => (
                                    <tr key={i}>
                                        <td><span className="purl-type-mini" style={{ color: TYPE_COLORS[p.type] || "#64748b" }}>{p.type}</span></td>
                                        <td className="lic-id">{p.namespace || "—"}</td>
                                        <td>{p.name}</td>
                                        <td>{p.version || "—"}</td>
                                        <td>{Object.keys(p.qualifiers).length > 0 ? Object.entries(p.qualifiers).map(([k, v]) => `${k}=${v}`).join(", ") : "—"}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">📦</span>
                    <h3>PURL Analyzer</h3>
                    <p>Open a CycloneDX BOM to analyze Package URLs: type breakdown, namespace stats, qualifier analysis</p>
                    {loaded && <p className="cbom-no-crypto">ℹ️ No PURLs found in this BOM</p>}
                </div>
            )}
        </div>
    );
}
