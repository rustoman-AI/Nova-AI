import { useState, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

// ─── Post-quantum unsafe algorithms ────────────────
const PQ_UNSAFE = new Set([
    "RSA", "DSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448",
    "X25519", "X448", "secp256r1", "secp384r1", "secp521r1", "P-256", "P-384", "P-521",
]);
const PQ_SAFE = new Set([
    "CRYSTALS-Kyber", "ML-KEM", "CRYSTALS-Dilithium", "ML-DSA",
    "FALCON", "SPHINCS+", "SLH-DSA", "FrodoKEM", "BIKE", "HQC",
]);
const FIPS_APPROVED = new Set([
    "AES", "AES-128", "AES-192", "AES-256", "SHA-256", "SHA-384", "SHA-512",
    "SHA-1", "SHA-224", "RSA", "ECDSA", "HMAC", "HKDF", "PBKDF2",
    "secp256r1", "secp384r1", "P-256", "P-384", "SHA3-256", "SHA3-384", "SHA3-512",
]);

// ─── Types ─────────────────────────────────────────
interface CryptoAlgorithm {
    componentName: string;
    algorithm: string;
    keyLength?: number;
    mode?: string;
    padding?: string;
    curve?: string;
    primitive?: string;
    pqReady: "safe" | "unsafe" | "unknown";
    fips: boolean;
}

interface CryptoCert {
    componentName: string;
    subject?: string;
    issuer?: string;
    notValidBefore?: string;
    notValidAfter?: string;
    signatureAlgorithm?: string;
    subjectPublicKeyAlgorithm?: string;
}

interface CryptoProtocol {
    componentName: string;
    type?: string;
    version?: string;
    cipherSuites: string[];
}

interface CryptoIkev2 {
    componentName: string;
    initiatorSpi?: string;
    responderSpi?: string;
    transforms: { type?: string; id?: string }[];
}

// ─── Main Component ────────────────────────────────
export default function CbomViewer() {
    const [algorithms, setAlgorithms] = useState<CryptoAlgorithm[]>([]);
    const [certs, setCerts] = useState<CryptoCert[]>([]);
    const [protocols, setProtocols] = useState<CryptoProtocol[]>([]);
    const [ikev2s, setIkev2s] = useState<CryptoIkev2[]>([]);
    const [loaded, setLoaded] = useState(false);

    const loadBom = useCallback(async () => {
        const f = await open({
            multiple: false,
            filters: [{ name: "CycloneDX BOM", extensions: ["json"] }],
            title: "Select CycloneDX 1.6 BOM",
        });
        if (!f) return;

        const content = await invoke<string>("read_file_contents", { path: f as string });
        const bom = JSON.parse(content);
        const components: any[] = bom.components || [];

        const algs: CryptoAlgorithm[] = [];
        const certList: CryptoCert[] = [];
        const protoList: CryptoProtocol[] = [];
        const ikeList: CryptoIkev2[] = [];

        for (const c of components) {
            const name = c.group ? `${c.group}/${c.name}` : (c.name || "?");
            const cp = c.cryptoProperties;
            if (!cp) continue;

            // Algorithm properties
            if (cp.algorithmProperties) {
                const ap = cp.algorithmProperties;
                const algoName = cp.algorithmProperties?.parameterSetIdentifier || cp.oid || c.name || "?";
                const pqStatus: "safe" | "unsafe" | "unknown" =
                    PQ_SAFE.has(algoName) ? "safe" :
                        PQ_UNSAFE.has(algoName) ? "unsafe" : "unknown";
                algs.push({
                    componentName: name,
                    algorithm: algoName,
                    keyLength: ap.parameterSetIdentifier ? undefined : (cp.algorithmProperties?.keyLength),
                    mode: ap.mode,
                    padding: ap.padding,
                    curve: ap.curve,
                    primitive: ap.primitive,
                    pqReady: pqStatus,
                    fips: FIPS_APPROVED.has(algoName),
                });
            }

            // Certificate properties
            if (cp.certificateProperties) {
                const cert = cp.certificateProperties;
                certList.push({
                    componentName: name,
                    subject: cert.subjectName,
                    issuer: cert.issuerName,
                    notValidBefore: cert.notValidBefore,
                    notValidAfter: cert.notValidAfter,
                    signatureAlgorithm: cert.signatureAlgorithmRef,
                    subjectPublicKeyAlgorithm: cert.subjectPublicKeyRef,
                });
            }

            // Protocol properties
            if (cp.protocolProperties) {
                const pp = cp.protocolProperties;
                const suites = (pp.cipherSuites || []).map((cs: any) =>
                    cs.name || cs.identifiers?.join(", ") || "unknown"
                );
                protoList.push({
                    componentName: name,
                    type: pp.type,
                    version: pp.version,
                    cipherSuites: suites,
                });
            }

            // IKEv2
            if (cp.protocolProperties?.ikev2TransformTypes) {
                const ike = cp.protocolProperties.ikev2TransformTypes;
                ikeList.push({
                    componentName: name,
                    transforms: (ike || []).map((t: any) => ({
                        type: t.type, id: t.id || t.name,
                    })),
                });
            }
        }

        setAlgorithms(algs);
        setCerts(certList);
        setProtocols(protoList);
        setIkev2s(ikeList);
        setLoaded(true);
    }, []);

    // Stats
    const stats = useMemo(() => {
        const pqUnsafe = algorithms.filter(a => a.pqReady === "unsafe").length;
        const pqSafe = algorithms.filter(a => a.pqReady === "safe").length;
        const fipsCount = algorithms.filter(a => a.fips).length;
        return { total: algorithms.length, pqUnsafe, pqSafe, fipsCount, certs: certs.length, protocols: protocols.length };
    }, [algorithms, certs, protocols]);

    const hasCrypto = algorithms.length > 0 || certs.length > 0 || protocols.length > 0;

    return (
        <div className="cbom-panel">
            <div className="analyze-header">
                <h2 className="pipe-title">CBOM Viewer</h2>
                <button className="exec-btn" onClick={loadBom}>📁 Open BOM</button>
                {hasCrypto && (
                    <div className="depgraph-stats">
                        <span className="depgraph-stat">{stats.total} algorithms</span>
                        <span className="depgraph-stat">{stats.certs} certs</span>
                        <span className="depgraph-stat">{stats.protocols} protocols</span>
                        {stats.pqUnsafe > 0 && <span className="depgraph-stat depgraph-stat-warn">⚠️ {stats.pqUnsafe} PQ-unsafe</span>}
                        {stats.pqSafe > 0 && <span className="depgraph-stat" style={{ color: "#22c55e", borderColor: "#22c55e" }}>✅ {stats.pqSafe} PQ-safe</span>}
                    </div>
                )}
            </div>

            {hasCrypto ? (
                <div className="cbom-content fade-in">
                    {/* Algorithms */}
                    {algorithms.length > 0 && (
                        <div className="cbom-section">
                            <h4>🔑 Algorithms ({algorithms.length})</h4>
                            <div className="lic-table-wrap">
                                <table className="lic-table">
                                    <thead>
                                        <tr>
                                            <th>Component</th>
                                            <th>Algorithm</th>
                                            <th>Key Len</th>
                                            <th>Mode</th>
                                            <th>Padding</th>
                                            <th>Curve</th>
                                            <th>PQ</th>
                                            <th>FIPS</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {algorithms.map((a, i) => (
                                            <tr key={i}>
                                                <td className="lic-id">{a.componentName}</td>
                                                <td><code>{a.algorithm}</code></td>
                                                <td>{a.keyLength ? `${a.keyLength} bit` : "—"}</td>
                                                <td>{a.mode || "—"}</td>
                                                <td>{a.padding || "—"}</td>
                                                <td>{a.curve || "—"}</td>
                                                <td>
                                                    <span className={`cbom-pq cbom-pq-${a.pqReady}`}>
                                                        {a.pqReady === "safe" ? "✅ PQ" : a.pqReady === "unsafe" ? "⚠️ Classical" : "❓"}
                                                    </span>
                                                </td>
                                                <td>{a.fips ? <span className="cbom-fips">FIPS</span> : "—"}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Certificates */}
                    {certs.length > 0 && (
                        <div className="cbom-section">
                            <h4>📜 Certificates ({certs.length})</h4>
                            <div className="cbom-cert-chain">
                                {certs.map((cert, i) => {
                                    const expired = cert.notValidAfter ? new Date(cert.notValidAfter) < new Date() : false;
                                    return (
                                        <div key={i} className={`cbom-cert-card ${expired ? "cbom-cert-expired" : ""}`}>
                                            <div className="cbom-cert-header">
                                                <span className="cbom-cert-icon">{expired ? "🔴" : "🟢"}</span>
                                                <span className="cbom-cert-subject">{cert.subject || cert.componentName}</span>
                                            </div>
                                            {cert.issuer && <div className="cbom-cert-row">Issuer: <b>{cert.issuer}</b></div>}
                                            {cert.notValidBefore && <div className="cbom-cert-row">Valid from: {cert.notValidBefore}</div>}
                                            {cert.notValidAfter && (
                                                <div className={`cbom-cert-row ${expired ? "cbom-cert-warn" : ""}`}>
                                                    Expires: <b>{cert.notValidAfter}</b> {expired && "⚠️ EXPIRED"}
                                                </div>
                                            )}
                                            {cert.signatureAlgorithm && <div className="cbom-cert-row">Sig: {cert.signatureAlgorithm}</div>}
                                            {i < certs.length - 1 && <div className="cbom-cert-arrow">↓</div>}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {/* Protocols */}
                    {protocols.length > 0 && (
                        <div className="cbom-section">
                            <h4>🌐 Protocols ({protocols.length})</h4>
                            {protocols.map((p, i) => (
                                <div key={i} className="cbom-proto-card">
                                    <div className="cbom-proto-header">
                                        <span className="cbom-proto-type">{p.type || "TLS"}</span>
                                        <span className="cbom-proto-ver">{p.version || "?"}</span>
                                        <span className="cbom-proto-name">{p.componentName}</span>
                                    </div>
                                    {p.cipherSuites.length > 0 && (
                                        <div className="cbom-cipher-list">
                                            {p.cipherSuites.map((cs, j) => (
                                                <span key={j} className="cbom-cipher">{cs}</span>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}

                    {/* IKEv2 */}
                    {ikev2s.length > 0 && (
                        <div className="cbom-section">
                            <h4>🔒 IKEv2 Transform Types ({ikev2s.length})</h4>
                            {ikev2s.map((ike, i) => (
                                <div key={i} className="cbom-proto-card">
                                    <div className="cbom-proto-header">
                                        <span className="cbom-proto-type">IKEv2</span>
                                        <span className="cbom-proto-name">{ike.componentName}</span>
                                    </div>
                                    <div className="cbom-cipher-list">
                                        {ike.transforms.map((t, j) => (
                                            <span key={j} className="cbom-cipher">{t.type}: {t.id}</span>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            ) : (
                <div className="pipe-empty">
                    <span className="pipe-empty-icon">🔐</span>
                    <h3>Cryptographic BOM Viewer</h3>
                    <p>Open a CycloneDX 1.6+ BOM with <code>cryptoProperties</code> to view algorithms, certificates, protocols, and post-quantum readiness</p>
                    {loaded && (
                        <p className="cbom-no-crypto">ℹ️ This BOM does not contain cryptographic properties (CBOM data)</p>
                    )}
                </div>
            )}
        </div>
    );
}
