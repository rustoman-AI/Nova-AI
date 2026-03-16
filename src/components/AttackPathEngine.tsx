import { useState, useEffect, useRef } from 'react';
import { listen } from '@tauri-apps/api/event';

/* ─── types ─── */
type ChainStage = { label: string; patched: boolean };
type ExploitChain = { id: string; stages: ChainStage[]; severity: string; entry: string; target: string; neutralized: boolean };
type TestResult = { node: string; vuln: string; testType: string; passed: boolean; details: string; ts: number };
type FuzzResult = { node: string; vuln: string; mutations: number; crashes: number; coverage: number; ts: number };
type StoredEvent = { type: string; ts: number; data: Record<string, unknown> };
type SimMove = { phase: string; attacker: string; defender: string; success: boolean; severity: number; path: string[]; ts: number };

/* ─── colors ─── */
const SEV_COLOR: Record<string, string> = { CRITICAL: '#ff4d4f', HIGH: '#fa8c16', MEDIUM: '#faad14', LOW: '#52c41a' };

export default function AttackPathEngine() {
    const [tab, setTab] = useState<'chains' | 'temporal' | 'tests' | 'fuzz' | 'events' | 'simulator'>('chains');
    const [chains, setChains] = useState<ExploitChain[]>([]);
    const [tests, setTests] = useState<TestResult[]>([]);
    const [fuzzes, setFuzzes] = useState<FuzzResult[]>([]);
    const [events, setEvents] = useState<StoredEvent[]>([]);
    const [simMoves, setSimMoves] = useState<SimMove[]>([]);
    const [graphVersion, setGraphVersion] = useState<'before' | 'after'>('before');
    const evRef = useRef(events);
    evRef.current = events;

    useEffect(() => {
        const unlisten = listen<Record<string, unknown>>('swarm-event', (e) => {
            const p = e.payload;
            const ts = Date.now();
            setEvents(prev => [...prev, { type: p.type as string, ts, data: p }]);

            if (p.type === 'ExploitChainDetected') {
                const stages = (p.stages as string[]).map(s => ({ label: s, patched: false }));
                setChains(prev => [...prev, {
                    id: p.chain_id as string,
                    stages,
                    severity: p.severity as string,
                    entry: p.entry_point as string,
                    target: p.target as string,
                    neutralized: false,
                }]);
            }
            if (p.type === 'TestPassed') {
                setTests(prev => [...prev, {
                    node: p.node_id as string, vuln: p.vuln_id as string,
                    testType: p.test_type as string, passed: p.passed as boolean,
                    details: p.details as string, ts,
                }]);
            }
            if (p.type === 'FuzzResult') {
                setFuzzes(prev => [...prev, {
                    node: p.node_id as string, vuln: p.vuln_id as string,
                    mutations: p.mutations as number, crashes: p.crashes as number,
                    coverage: p.coverage_pct as number, ts,
                }]);
            }
            if (p.type === 'ExploitSimulation') {
                setSimMoves(prev => [...prev, {
                    phase: p.phase as string, attacker: p.attacker_action as string,
                    defender: p.defender_response as string, success: p.success as boolean,
                    severity: p.severity_score as number, path: p.node_path as string[], ts,
                }]);
            }
            if (p.type === 'PatchApplied') {
                setChains(prev => prev.map(c => ({
                    ...c,
                    stages: c.stages.map(s => s.label.includes(p.node_id as string) ? { ...s, patched: true } : s),
                    neutralized: c.stages.every(s => s.patched || s.label.includes(p.node_id as string)),
                })));
                setGraphVersion('after');
            }
        });
        return () => { unlisten.then(f => f()); };
    }, []);

    const TABS: { id: typeof tab; label: string; icon: string }[] = [
        { id: 'chains', label: 'Exploit Chains', icon: '⛓️' },
        { id: 'temporal', label: 'Temporal Graph', icon: '🕐' },
        { id: 'tests', label: 'Test Agent', icon: '🧪' },
        { id: 'fuzz', label: 'Fuzz Agent', icon: '🔀' },
        { id: 'events', label: 'Event Store', icon: '📡' },
        { id: 'simulator', label: 'Exploit Sim', icon: '🎯' },
    ];

    return (
        <div style={{ padding: '20px', minHeight: '100vh', background: 'radial-gradient(ellipse at bottom, #0d1117 0%, #03040b 100%)', color: '#fff', fontFamily: "'Inter', sans-serif" }}>
            <h2 style={{ margin: '0 0 4px', fontSize: '1.3rem' }}>🔎 Attack-Path AI Engine</h2>
            <p style={{ margin: '0 0 16px', fontSize: '0.8rem', color: '#8b949e' }}>MetaGraph + Graph Algorithms + LLM Reasoning • Hyperscale Security</p>

            {/* Sub-tabs */}
            <div style={{ display: 'flex', gap: '4px', marginBottom: '16px', flexWrap: 'wrap' }}>
                {TABS.map(t => (
                    <button key={t.id} onClick={() => setTab(t.id)}
                        style={{ padding: '6px 14px', borderRadius: '8px', border: '1px solid ' + (tab === t.id ? '#4facfe' : '#21262d'), background: tab === t.id ? '#4facfe22' : '#161b22', color: tab === t.id ? '#fff' : '#8b949e', cursor: 'pointer', fontSize: '0.8rem' }}>
                        {t.icon} {t.label}
                    </button>
                ))}
            </div>

            {/* ═══ EXPLOIT CHAINS ═══ */}
            {tab === 'chains' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {chains.length === 0 && <EmptyState icon="⛓️" text="Run REPLAY DEMO to detect exploit chains" />}
                    {chains.map(chain => (
                        <div key={chain.id} style={{ background: 'rgba(22,27,34,0.5)', border: `1px solid ${chain.neutralized ? '#52c41a33' : (SEV_COLOR[chain.severity] || '#ff4d4f') + '33'}`, borderRadius: '14px', padding: '20px', backdropFilter: 'blur(10px)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                                <div>
                                    <span style={{ fontSize: '1rem', fontWeight: 700 }}>{chain.id}</span>
                                    <span style={{ marginLeft: '10px', fontSize: '0.75rem', padding: '2px 8px', borderRadius: '4px', background: (SEV_COLOR[chain.severity] || '#ff4d4f') + '22', color: SEV_COLOR[chain.severity] || '#ff4d4f', fontWeight: 600 }}>{chain.severity}</span>
                                </div>
                                {chain.neutralized && <span style={{ color: '#52c41a', fontWeight: 700, fontSize: '0.85rem' }}>✅ NEUTRALIZED</span>}
                            </div>
                            <div style={{ fontSize: '0.8rem', color: '#8b949e', marginBottom: '12px' }}>
                                Entry: <code style={{ color: '#4facfe' }}>{chain.entry}</code> → Target: <code style={{ color: '#ff4d4f' }}>{chain.target}</code>
                            </div>
                            {/* Chain visualization */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0', flexWrap: 'wrap' }}>
                                {chain.stages.map((stage, i) => (
                                    <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
                                        <div style={{
                                            padding: '8px 14px', borderRadius: '8px', fontSize: '0.8rem',
                                            background: stage.patched ? '#52c41a15' : '#ff4d4f15',
                                            border: `1px solid ${stage.patched ? '#52c41a44' : '#ff4d4f44'}`,
                                            color: stage.patched ? '#52c41a' : '#ff4d4f',
                                            textDecoration: stage.patched ? 'line-through' : 'none',
                                            position: 'relative',
                                        }}>
                                            {stage.label}
                                            {stage.patched && <span style={{ position: 'absolute', top: '-6px', right: '-6px', fontSize: '0.7rem' }}>🛡️</span>}
                                        </div>
                                        {i < chain.stages.length - 1 && <span style={{ margin: '0 6px', color: '#484f58', fontSize: '1.2rem' }}>→</span>}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* ═══ TEMPORAL GRAPH ═══ */}
            {tab === 'temporal' && (
                <div style={{ background: 'rgba(22,27,34,0.5)', border: '1px solid #30363d', borderRadius: '14px', padding: '20px', backdropFilter: 'blur(10px)' }}>
                    <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
                        <button onClick={() => setGraphVersion('before')} style={tvBtn(graphVersion === 'before', '#ff4d4f')}>🔴 Before Patch</button>
                        <button onClick={() => setGraphVersion('after')} style={tvBtn(graphVersion === 'after', '#52c41a')}>🟢 After Patch</button>
                    </div>
                    <svg viewBox="0 0 600 300" style={{ width: '100%', maxHeight: '320px' }}>
                        {/* Nodes */}
                        {TEMPORAL_NODES.map(n => (
                            <g key={n.id}>
                                <circle cx={n.x} cy={n.y} r={20} fill={graphVersion === 'before' ? n.colorBefore : n.colorAfter} opacity={0.8} />
                                <text x={n.x} y={n.y + 4} textAnchor="middle" fill="#fff" fontSize="9" fontWeight="600">{n.label}</text>
                                <text x={n.x} y={n.y + 32} textAnchor="middle" fill="#8b949e" fontSize="7">{graphVersion === 'before' ? n.statusBefore : n.statusAfter}</text>
                            </g>
                        ))}
                        {/* Edges */}
                        {TEMPORAL_EDGES.map((e, i) => {
                            const from = TEMPORAL_NODES.find(n => n.id === e.from)!;
                            const to = TEMPORAL_NODES.find(n => n.id === e.to)!;
                            const color = graphVersion === 'before' ? '#ff4d4f' : (e.severed ? '#21262d' : '#52c41a');
                            return (
                                <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                                    stroke={color} strokeWidth={e.severed && graphVersion === 'after' ? 1 : 2}
                                    strokeDasharray={e.severed && graphVersion === 'after' ? '4,4' : ''} opacity={0.6} />
                            );
                        })}
                    </svg>
                    <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginTop: '8px', fontSize: '0.75rem', color: '#8b949e' }}>
                        <span><span style={{ color: '#ff4d4f' }}>●</span> Vulnerable</span>
                        <span><span style={{ color: '#52c41a' }}>●</span> Patched</span>
                        <span style={{ textDecoration: 'line-through' }}>— Severed</span>
                    </div>
                </div>
            )}

            {/* ═══ TEST AGENT ═══ */}
            {tab === 'tests' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {tests.length === 0 && <EmptyState icon="🧪" text="Test results will appear during REPLAY DEMO" />}
                    {tests.map((t, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 16px', background: 'rgba(22,27,34,0.5)', border: `1px solid ${t.passed ? '#52c41a33' : '#ff4d4f33'}`, borderRadius: '10px' }}>
                            <span style={{ fontSize: '1.3rem' }}>{t.passed ? '✅' : '❌'}</span>
                            <div style={{ flex: 1 }}>
                                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#c9d1d9' }}>{t.node} <code style={{ color: '#4facfe', fontSize: '0.75rem' }}>{t.vuln}</code></div>
                                <div style={{ fontSize: '0.75rem', color: '#8b949e' }}>{t.details}</div>
                            </div>
                            <span style={{ fontSize: '0.7rem', padding: '2px 8px', borderRadius: '4px', background: '#161b22', color: '#8b949e', textTransform: 'uppercase' }}>{t.testType}</span>
                        </div>
                    ))}
                </div>
            )}

            {/* ═══ FUZZ AGENT ═══ */}
            {tab === 'fuzz' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {fuzzes.length === 0 && <EmptyState icon="🔀" text="Fuzz results will appear during REPLAY DEMO" />}
                    {fuzzes.map((f, i) => (
                        <div key={i} style={{ padding: '16px', background: 'rgba(22,27,34,0.5)', border: '1px solid #30363d', borderRadius: '10px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                                <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{f.node}</span>
                                <code style={{ color: '#4facfe', fontSize: '0.75rem' }}>{f.vuln}</code>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
                                <MiniMetric label="Mutations" value={f.mutations.toLocaleString()} color="#722ed1" />
                                <MiniMetric label="Crashes" value={String(f.crashes)} color={f.crashes === 0 ? '#52c41a' : '#ff4d4f'} />
                                <MiniMetric label="Coverage" value={`${f.coverage.toFixed(1)}%`} color="#4facfe" />
                            </div>
                            {/* Coverage bar */}
                            <div style={{ marginTop: '8px', height: '6px', borderRadius: '3px', background: '#21262d', overflow: 'hidden' }}>
                                <div style={{ width: `${f.coverage}%`, height: '100%', borderRadius: '3px', background: 'linear-gradient(90deg, #4facfe, #00f2fe)', transition: 'width 1s' }} />
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* ═══ EVENT STORE ═══ */}
            {tab === 'events' && (
                <div style={{ background: 'rgba(22,27,34,0.5)', border: '1px solid #30363d', borderRadius: '14px', padding: '16px', backdropFilter: 'blur(10px)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
                        <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>📡 Persisted Events ({events.length})</span>
                        <button onClick={() => setEvents([])} style={{ padding: '4px 10px', borderRadius: '6px', border: '1px solid #30363d', background: '#161b22', color: '#8b949e', cursor: 'pointer', fontSize: '0.7rem' }}>Clear</button>
                    </div>
                    <div style={{ maxHeight: '400px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.72rem' }}>
                        {events.length === 0 && <div style={{ color: '#484f58', padding: '20px', textAlign: 'center' }}>No events captured yet</div>}
                        {events.slice().reverse().map((ev, i) => (
                            <div key={i} style={{ padding: '4px 8px', borderBottom: '1px solid #21262d11', display: 'flex', gap: '8px' }}>
                                <span style={{ color: '#484f58', minWidth: '80px' }}>{new Date(ev.ts).toLocaleTimeString()}</span>
                                <span style={{ color: EVENT_COLORS[ev.type] || '#8b949e', fontWeight: 600, minWidth: '160px' }}>{ev.type}</span>
                                <span style={{ color: '#6e7681', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{JSON.stringify(ev.data).slice(0, 100)}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* ═══ EXPLOIT SIMULATOR ═══ */}
            {tab === 'simulator' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>🎯 Red Team vs Blue Team — Exploit Simulation</span>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <button onClick={() => setSimMoves([])} style={{ padding: '4px 10px', borderRadius: '6px', border: '1px solid #30363d', background: '#161b22', color: '#8b949e', cursor: 'pointer', fontSize: '0.7rem' }}>Clear</button>
                            <button onClick={async () => { try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('run_exploit_simulation'); } catch(e) { console.error(e); } }}
                                style={{ padding: '6px 14px', borderRadius: '8px', border: '1px solid #ff4d4f', background: '#ff4d4f22', color: '#ff4d4f', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 700 }}>
                                🚀 Launch Simulation
                            </button>
                        </div>
                    </div>
                    {simMoves.length === 0 && <EmptyState icon="🎯" text='Click "Launch Simulation" to start Red Team attack' />}
                    {simMoves.map((m, i) => (
                        <div key={i} style={{ background: 'rgba(22,27,34,0.6)', border: `1px solid ${m.success ? '#ff4d4f33' : '#52c41a33'}`, borderRadius: '12px', padding: '14px 16px', backdropFilter: 'blur(10px)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                                <span style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.1em', color: PHASE_COLORS[m.phase] || '#8b949e', fontWeight: 700 }}>
                                    {PHASE_ICONS[m.phase] || '📍'} {m.phase}
                                </span>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <span style={{ fontSize: '0.7rem', color: '#8b949e' }}>{new Date(m.ts).toLocaleTimeString()}</span>
                                    <span style={{ fontSize: '0.7rem', padding: '2px 8px', borderRadius: '4px', fontWeight: 700, background: m.success ? '#ff4d4f22' : '#52c41a22', color: m.success ? '#ff4d4f' : '#52c41a' }}>
                                        {m.success ? '🔴 ATTACKER' : '🔵 DEFENDER'}
                                    </span>
                                </div>
                            </div>
                            <div style={{ fontSize: '0.82rem', color: '#f0883e', marginBottom: '4px' }}>{m.attacker}</div>
                            <div style={{ fontSize: '0.82rem', color: '#4facfe', marginBottom: '8px' }}>{m.defender}</div>
                            {/* Severity bar */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                                <span style={{ fontSize: '0.7rem', color: '#8b949e', minWidth: '55px' }}>Severity</span>
                                <div style={{ flex: 1, height: '5px', borderRadius: '3px', background: '#21262d', overflow: 'hidden' }}>
                                    <div style={{ width: `${m.severity * 10}%`, height: '100%', borderRadius: '3px', background: m.severity > 7 ? '#ff4d4f' : m.severity > 4 ? '#fa8c16' : '#52c41a', transition: 'width 0.5s' }} />
                                </div>
                                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: m.severity > 7 ? '#ff4d4f' : m.severity > 4 ? '#fa8c16' : '#52c41a', minWidth: '30px' }}>{m.severity.toFixed(1)}</span>
                            </div>
                            {/* Node path */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
                                {m.path.map((node, j) => (
                                    <span key={j} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                        <code style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: '4px', background: node === 'BLOCKED' ? '#ff4d4f22' : node === 'SIMULATION_COMPLETE' ? '#52c41a22' : '#161b22', color: node === 'BLOCKED' ? '#ff4d4f' : node === 'SIMULATION_COMPLETE' ? '#52c41a' : '#8b949e' }}>{node}</code>
                                        {j < m.path.length - 1 && <span style={{ color: '#484f58', fontSize: '0.8rem' }}>→</span>}
                                    </span>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

/* ─── helpers ─── */
const EVENT_COLORS: Record<string, string> = {
    ThreatDetected: '#ff4d4f', ReviewRequested: '#722ed1', ReviewResult: '#eb2f96',
    PatchApplied: '#52c41a', ComplianceResult: '#4facfe', Log: '#8b949e',
    TestPassed: '#13c2c2', FuzzResult: '#faad14', ExploitChainDetected: '#ff4d4f',
    ExploitSimulation: '#f0883e', TestFailed: '#ff4d4f', DependencyRisk: '#fa8c16', PolicyViolation: '#eb2f96',
    RollbackPerformed: '#fa8c16',
};

const PHASE_COLORS: Record<string, string> = { recon: '#4facfe', exploit: '#ff4d4f', escalate: '#f0883e', exfiltrate: '#eb2f96', defense: '#52c41a' };
const PHASE_ICONS: Record<string, string> = { recon: '🔍', exploit: '💉', escalate: '⬆️', exfiltrate: '📤', defense: '🛡️' };

function tvBtn(active: boolean, color: string): React.CSSProperties {
    return { padding: '6px 16px', borderRadius: '8px', border: `1px solid ${active ? color : '#21262d'}`, background: active ? color + '22' : '#161b22', color: active ? '#fff' : '#8b949e', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600 };
}

function EmptyState({ icon, text }: { icon: string; text: string }) {
    return <div style={{ textAlign: 'center', padding: '40px', color: '#484f58' }}><div style={{ fontSize: '2rem', marginBottom: '8px' }}>{icon}</div><div style={{ fontStyle: 'italic' }}>{text}</div></div>;
}

function MiniMetric({ label, value, color }: { label: string; value: string; color: string }) {
    return (
        <div style={{ textAlign: 'center', padding: '8px', background: '#161b22', borderRadius: '8px' }}>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color }}>{value}</div>
            <div style={{ fontSize: '0.7rem', color: '#8b949e' }}>{label}</div>
        </div>
    );
}

const TEMPORAL_NODES = [
    { id: 'http', x: 80, y: 60, label: 'HTTP Input', colorBefore: '#ff4d4f', colorAfter: '#52c41a', statusBefore: 'ENTRY', statusAfter: 'SANITIZED' },
    { id: 'api', x: 220, y: 60, label: 'api_server', colorBefore: '#ff4d4f', colorAfter: '#52c41a', statusBefore: 'SQLi VULN', statusAfter: 'PATCHED' },
    { id: 'db', x: 360, y: 60, label: 'credentials', colorBefore: '#ff4d4f', colorAfter: '#52c41a', statusBefore: 'LEAKED', statusAfter: 'SAFE' },
    { id: 'web', x: 220, y: 150, label: 'web_handler', colorBefore: '#ff4d4f', colorAfter: '#52c41a', statusBefore: 'XSS VULN', statusAfter: 'PATCHED' },
    { id: 'admin', x: 500, y: 60, label: 'admin_token', colorBefore: '#ff4d4f', colorAfter: '#52c41a', statusBefore: 'EXPOSED', statusAfter: 'SAFE' },
    { id: 'deploy', x: 500, y: 150, label: 'deploy_script', colorBefore: '#ff4d4f', colorAfter: '#52c41a', statusBefore: 'CMD INJ', statusAfter: 'PATCHED' },
    { id: 'shell', x: 360, y: 240, label: 'Root Shell', colorBefore: '#ff4d4f', colorAfter: '#21262d', statusBefore: 'REACHABLE', statusAfter: 'BLOCKED' },
];

const TEMPORAL_EDGES = [
    { from: 'http', to: 'api', severed: false },
    { from: 'api', to: 'db', severed: true },
    { from: 'db', to: 'admin', severed: true },
    { from: 'admin', to: 'deploy', severed: true },
    { from: 'deploy', to: 'shell', severed: true },
    { from: 'http', to: 'web', severed: false },
    { from: 'web', to: 'shell', severed: true },
];
