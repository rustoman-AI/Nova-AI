import React, { useState } from 'react';
import { QueryEngineAPI, DatalogResult } from './QueryEngineApi';

type DatalogTab = 'exploit' | 'copyleft' | 'trust' | 'blast';

interface DatalogQueryPanelProps {
    sbomPath?: string;
    sourceRoot?: string;
    onHighlightProofChain?: (paths: string[][]) => void;
}

export const DatalogQueryPanel: React.FC<DatalogQueryPanelProps> = ({ sbomPath, sourceRoot, onHighlightProofChain }) => {
    const [result, setResult] = useState<DatalogResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<DatalogTab>('exploit');

    const runQuery = async () => {
        setLoading(true);
        setError(null);
        try {
            const { invoke } = await import('@tauri-apps/api/core');
            // Read SBOM if path provided, otherwise null
            let sbomContent: string | undefined;
            if (sbomPath?.trim()) {
                sbomContent = await invoke<string>('read_file_contents', { path: sbomPath });
            }
            const results = await QueryEngineAPI.computeAttackPaths(sbomContent, sourceRoot);
            setResult(results);
        } catch (e: any) {
            setError(e.toString());
        } finally {
            setLoading(false);
        }
    };

    const TABS: { key: DatalogTab; icon: string; label: string; color: string; count: number }[] = [
        { key: 'exploit', icon: '💀', label: 'Exploit Paths', color: '#ff4d4f', count: result?.exploitation_paths.length ?? 0 },
        { key: 'copyleft', icon: '📜', label: 'Copyleft Risk', color: '#fa8c16', count: result?.copyleft_risks.length ?? 0 },
        { key: 'trust', icon: '🛡️', label: 'Trust Decay', color: '#722ed1', count: result?.trust_decay.length ?? 0 },
        { key: 'blast', icon: '💥', label: 'Blast Radius', color: '#1890ff', count: result?.blast_radius.length ?? 0 },
    ];

    const short = (s: string) => {
        const parts = s.split('/');
        return parts[parts.length - 1] || s;
    };

    return (
        <div style={{
            background: '#16162a', border: '1px solid #2a2a4a', borderRadius: 10, padding: 14,
            display: 'flex', flexDirection: 'column', gap: 10,
        }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #2a2a4a' }}>
                <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#e0e0e0', letterSpacing: 0.5 }}>
                        DARPA Logic Engine <span style={{ color: '#722ed1', fontSize: 11 }}>(Datalog)</span>
                    </div>
                    <div style={{ fontSize: 10, color: '#666', marginTop: 2 }}>
                        Cross-layer Datalog inference: AST → SBOM → Vulnerabilities
                    </div>
                </div>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: result ? '#52c41a' : '#faad14', animation: 'pulse 2s infinite' }} />
            </div>

            {/* Run button */}
            <button onClick={runQuery} disabled={loading}
                style={{
                    padding: '8px 16px', borderRadius: 8, border: '1px solid #722ed1',
                    background: loading ? '#722ed122' : '#722ed133', color: '#b37feb',
                    fontSize: 12, fontWeight: 700, cursor: loading ? 'default' : 'pointer',
                    transition: 'all .15s',
                }}>
                {loading ? '⏳ Executing Crepe Inference...' : '▶ Run Datalog Analysis'}
            </button>

            {!sbomPath?.trim() && (
                <div style={{ fontSize: 10, color: '#666', fontStyle: 'italic' }}>
                    💡 Add SBOM JSON path for deeper analysis (optional)
                </div>
            )}

            {error && (
                <div style={{ fontSize: 11, color: '#ff4d4f', background: '#ff4d4f11', padding: 8, borderRadius: 6, border: '1px solid #ff4d4f33' }}>
                    ❌ {error}
                </div>
            )}

            {/* Stats bar */}
            {result && (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {[
                        { label: 'Facts', value: result.stats.total_facts, color: '#52c41a' },
                        { label: 'Derived', value: result.stats.total_derived, color: '#1890ff' },
                        { label: 'Components', value: result.stats.components_analyzed, color: '#722ed1' },
                        { label: 'Vulns', value: result.stats.vulnerabilities_analyzed, color: '#ff4d4f' },
                        { label: 'Entry Pts', value: result.stats.entry_points_analyzed, color: '#fa8c16' },
                    ].map(s => (
                        <div key={s.label} style={{ flex: 1, textAlign: 'center', padding: '6px 4px', background: '#0e0e1a', borderRadius: 6, minWidth: 60 }}>
                            <div style={{ fontSize: 16, fontWeight: 800, color: s.color }}>{s.value}</div>
                            <div style={{ fontSize: 8, color: '#555', textTransform: 'uppercase', letterSpacing: 0.5 }}>{s.label}</div>
                        </div>
                    ))}
                </div>
            )}

            {/* Tabs */}
            {result && (
                <>
                    <div style={{ display: 'flex', gap: 3 }}>
                        {TABS.map(t => (
                            <button key={t.key} onClick={() => setActiveTab(t.key)}
                                style={{
                                    flex: 1, padding: '6px 4px', borderRadius: 6, border: `1px solid ${activeTab === t.key ? t.color : '#2a2a4a'}`,
                                    background: activeTab === t.key ? `${t.color}18` : 'transparent',
                                    color: activeTab === t.key ? t.color : '#666', cursor: 'pointer',
                                    fontSize: 10, fontWeight: 700, transition: 'all .15s', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2,
                                }}>
                                <span>{t.icon} {t.count}</span>
                                <span style={{ fontSize: 8 }}>{t.label}</span>
                            </button>
                        ))}
                    </div>

                    {/* Tab Content */}
                    <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {/* Exploitation Paths */}
                        {activeTab === 'exploit' && result.exploitation_paths.map((p, i) => (
                            <div key={i}
                                onClick={() => onHighlightProofChain?.([p.proof_chain])}
                                style={{
                                    background: '#0e0e1a', borderRadius: 6, padding: 8, border: '1px solid #ff4d4f22', fontSize: 10,
                                    cursor: onHighlightProofChain ? 'pointer' : 'default',
                                    transition: 'all 0.2s',
                                }}
                                onMouseEnter={(e) => { if (onHighlightProofChain) e.currentTarget.style.boxShadow = '0 0 8px #ff4d4f44'; }}
                                onMouseLeave={(e) => { if (onHighlightProofChain) e.currentTarget.style.boxShadow = 'none'; }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                    <span style={{ color: '#ff4d4f', fontWeight: 700 }}>💀 Proof of Concept: {p.vulnerability_id}</span>
                                    <span style={{ color: '#ff7875', fontSize: 9 }}>{onHighlightProofChain ? '⚡ Click to view' : 'Exploitable Path'}</span>
                                </div>

                                <div style={{ background: '#00000044', borderRadius: 4, padding: '6px 8px', marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                                    {p.proof_chain.map((step, stepIdx) => (
                                        <div key={stepIdx} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                            {stepIdx > 0 && <span style={{ color: '#555', fontSize: 8, marginLeft: 2 }}>↳</span>}
                                            <span style={{
                                                color: stepIdx === 0 ? '#52c41a' : stepIdx === p.proof_chain.length - 1 ? '#ff4d4f' : '#8c8c8c',
                                                background: stepIdx === 0 ? '#52c41a11' : stepIdx === p.proof_chain.length - 1 ? '#ff4d4f11' : 'transparent',
                                                padding: '1px 4px', borderRadius: 3,
                                                fontWeight: stepIdx === 0 || stepIdx === p.proof_chain.length - 1 ? 700 : 400
                                            }}>
                                                {short(step)}
                                            </span>
                                            {stepIdx === 0 && <span style={{ fontSize: 8, color: '#52c41a', fontStyle: 'italic' }}>(Origin)</span>}
                                            {stepIdx === p.proof_chain.length - 1 && <span style={{ fontSize: 8, color: '#ff4d4f', fontStyle: 'italic' }}>(Impact)</span>}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                        {activeTab === 'exploit' && result.exploitation_paths.length === 0 && (
                            <div style={{ textAlign: 'center', padding: 20, color: '#52c41a', fontSize: 11 }}>✅ No exploitation paths found</div>
                        )}

                        {/* Copyleft Risks */}
                        {activeTab === 'copyleft' && result.copyleft_risks.map((c, i) => (
                            <div key={i} style={{ background: '#0e0e1a', borderRadius: 6, padding: 8, border: '1px solid #fa8c1622', fontSize: 10 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                    <span style={{ color: '#fa8c16', fontWeight: 700 }}>📜 {c.license}</span>
                                    <span style={{ color: '#ffc069', fontSize: 9 }}>Propagates</span>
                                </div>
                                <div style={{ color: '#8c8c8c' }}>
                                    <span style={{ color: '#555' }}>From: </span><span style={{ color: '#ffc069' }}>{short(c.source_component)}</span>
                                    <span style={{ color: '#333', margin: '0 4px' }}>→</span>
                                    <span style={{ color: '#fa8c16' }}>{short(c.affected_component)}</span>
                                </div>
                            </div>
                        ))}
                        {activeTab === 'copyleft' && result.copyleft_risks.length === 0 && (
                            <div style={{ textAlign: 'center', padding: 20, color: '#52c41a', fontSize: 11 }}>✅ No copyleft propagation risks</div>
                        )}

                        {/* Trust Decay */}
                        {activeTab === 'trust' && result.trust_decay.map((t, i) => (
                            <div key={i} style={{ background: '#0e0e1a', borderRadius: 6, padding: 8, border: '1px solid #722ed122', fontSize: 10 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                    <span style={{ color: '#b37feb', fontWeight: 700 }}>🛡️ {short(t.component)}</span>
                                    <span style={{
                                        color: t.downstream_count > 5 ? '#ff4d4f' : t.downstream_count > 0 ? '#fa8c16' : '#52c41a',
                                        fontSize: 9, fontWeight: 700,
                                    }}>
                                        {t.downstream_count} downstream
                                    </span>
                                </div>
                                <div style={{ color: '#8c8c8c' }}>
                                    <span style={{ color: '#555' }}>Reason: </span>
                                    <span style={{
                                        color: '#b37feb', background: '#722ed118', padding: '1px 6px', borderRadius: 4, fontSize: 9,
                                    }}>
                                        {t.reason.replace('_', ' ')}
                                    </span>
                                </div>
                            </div>
                        ))}
                        {activeTab === 'trust' && result.trust_decay.length === 0 && (
                            <div style={{ textAlign: 'center', padding: 20, color: '#52c41a', fontSize: 11 }}>✅ No trust decay chains</div>
                        )}

                        {/* Blast Radius */}
                        {activeTab === 'blast' && result.blast_radius.map((b, i) => (
                            <div key={i} style={{ background: '#0e0e1a', borderRadius: 6, padding: 8, border: '1px solid #1890ff22', fontSize: 10 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                    <span style={{ color: '#ff4d4f', fontWeight: 700 }}>💥 {b.vulnerability_id}</span>
                                    <span style={{
                                        color: b.total_affected > 10 ? '#ff4d4f' : b.total_affected > 3 ? '#fa8c16' : '#1890ff',
                                        fontSize: 9, fontWeight: 700,
                                    }}>
                                        {b.total_affected} affected
                                    </span>
                                </div>
                                <div style={{ color: '#8c8c8c', marginBottom: 4 }}>
                                    <span style={{ color: '#555' }}>Source: </span>
                                    <span style={{ color: '#69c0ff' }}>{short(b.vulnerable_component)}</span>
                                </div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                                    {b.affected_components.slice(0, 8).map((a, j) => (
                                        <span key={j} style={{
                                            fontSize: 8, padding: '1px 5px', borderRadius: 3,
                                            background: '#1890ff11', border: '1px solid #1890ff33', color: '#69c0ff',
                                        }}>
                                            {short(a)}
                                        </span>
                                    ))}
                                    {b.affected_components.length > 8 && (
                                        <span style={{ fontSize: 8, color: '#555' }}>+{b.affected_components.length - 8} more</span>
                                    )}
                                </div>
                            </div>
                        ))}
                        {activeTab === 'blast' && result.blast_radius.length === 0 && (
                            <div style={{ textAlign: 'center', padding: 20, color: '#52c41a', fontSize: 11 }}>✅ No blast radius concerns</div>
                        )}
                    </div>
                </>
            )}
        </div>
    );
};
