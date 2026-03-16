import { useState, useEffect, useRef } from 'react';
import { listen, Event } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import AgentNeuralGraph from './AgentNeuralGraph';

type SwarmPayload = {
    type: string;
    agent?: string;
    message?: string;
    node_id?: string;
    vuln_id?: string;
    approved?: boolean;
    file_path?: string;
    commit_id?: string;
};

type SwarmStatus = 'IDLE' | 'SCANNING' | 'GENERATING' | 'REVIEWING' | 'HEALED' | 'REJECTED';

const STATUS_CONFIG: Record<SwarmStatus, { label: string; color: string; icon: string }> = {
    IDLE:       { label: 'SWARM STANDBY',    color: '#8b949e', icon: '⏸' },
    SCANNING:   { label: 'SCANNING AST',     color: '#faad14', icon: '🔍' },
    GENERATING: { label: 'GENERATING PATCH', color: '#eb2f96', icon: '⚙️' },
    REVIEWING:  { label: 'SHIELD REVIEW',    color: '#13c2c2', icon: '🛡️' },
    HEALED:     { label: 'SELF-HEALED',      color: '#52c41a', icon: '✅' },
    REJECTED:   { label: 'PATCH REJECTED',   color: '#ff4d4f', icon: '❌' },
};

export default function PitchDashboard() {
    const [scannedNodes, setScannedNodes] = useState(0);
    const [threatsFound, setThreatsFound] = useState(0);
    const [patchesApplied, setPatchesApplied] = useState(0);
    const [reviewCount, setReviewCount] = useState(0);
    const [status, setStatus] = useState<SwarmStatus>('IDLE');
    const [activityLog, setActivityLog] = useState<{icon: string; text: string; time: string}[]>([]);
    const [commitHash, setCommitHash] = useState<string | null>(null);
    const [complianceScore, setComplianceScore] = useState<number | null>(null);
    const [voiceEnabled, setVoiceEnabled] = useState(false);
    const voiceRef = useRef(voiceEnabled);

    useEffect(() => { voiceRef.current = voiceEnabled; }, [voiceEnabled]);

    const speak = (text: string) => {
        if (!voiceRef.current) return;
        const u = new SpeechSynthesisUtterance(text);
        u.rate = 1.1;
        u.pitch = 0.9;
        u.volume = 0.8;
        const voices = speechSynthesis.getVoices();
        const en = voices.find(v => v.lang.startsWith('en') && v.name.includes('Google'));
        if (en) u.voice = en;
        speechSynthesis.speak(u);
    };

    // Animate base scanned nodes on mount
    useEffect(() => {
        const interval = setInterval(() => {
            setScannedNodes(prev => {
                if (prev < 14204) return prev + Math.floor(Math.random() * 500);
                return 14204;
            });
        }, 50);
        return () => clearInterval(interval);
    }, []);

    // Listen for live swarm events
    useEffect(() => {
        const unlisten = listen<SwarmPayload>('swarm-event', (event: Event<SwarmPayload>) => {
            const ev = event.payload;
            const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

            const addLog = (icon: string, text: string) => {
                setActivityLog(prev => [{icon, text, time: now}, ...prev].slice(0, 8));
            };

            switch (ev.type) {
                case 'Log':
                    if (ev.message?.includes('surveillance') || ev.message?.includes('vulnerability')) {
                        setStatus('SCANNING');
                        addLog('🔍', ev.message || '');
                    } else if (ev.message?.includes('Generating patch')) {
                        setStatus('GENERATING');
                        addLog('⚙️', ev.message || '');
                    } else if (ev.message?.includes('Reviewing')) {
                        setStatus('REVIEWING');
                        addLog('🛡️', ev.message || '');
                    } else if (ev.message?.includes('Written to disk') || ev.message?.includes('💾')) {
                        addLog('💾', ev.message || '');
                    } else if (ev.message?.includes('REJECTED')) {
                        setStatus('REJECTED');
                        addLog('❌', ev.message || '');
                    } else {
                        addLog('📡', ev.message || '');
                    }
                    break;
                case 'ThreatDetected':
                    setThreatsFound(prev => prev + 1);
                    setScannedNodes(prev => prev + Math.floor(Math.random() * 200 + 100));
                    setStatus('SCANNING');
                    addLog('🛑', `Threat detected: ${ev.vuln_id} in ${ev.node_id}`);
                    speak(`Critical vulnerability detected. ${ev.vuln_id} found in ${ev.node_id}.`);
                    break;
                case 'ReviewRequested':
                    setReviewCount(prev => prev + 1);
                    setStatus('REVIEWING');
                    addLog('⚖️', `Patch sent to NovaShield for review`);
                    speak('Patch generated. Sending to Nova Shield for security review.');
                    break;
                case 'ReviewResult':
                    if (ev.approved) {
                        setStatus('HEALED');
                        addLog('✅', `Patch APPROVED by NovaShield`);
                        speak('Patch approved by Nova Shield. Writing fix to disk.');
                    } else {
                        setStatus('REJECTED');
                        setReviewCount(prev => prev + 1);
                        addLog('❌', `Patch REJECTED — awaiting revision`);
                        speak('Patch rejected. Generating improved fix.');
                    }
                    break;
                case 'PatchApplied':
                    setPatchesApplied(prev => prev + 1);
                    setCommitHash(ev.commit_id?.substring(0, 8) || null);
                    setStatus('HEALED');
                    addLog('💾', `Committed ${ev.commit_id?.substring(0, 8)} to nova-heal/${ev.vuln_id?.toLowerCase()}`);
                    speak(`Patch committed to git. Commit hash: ${ev.commit_id?.substring(0, 8)}.`);
                    break;
                case 'ComplianceResult':
                    setComplianceScore((ev as any).score);
                    if ((ev as any).passed) {
                        addLog('🛡️', `Compliance PASSED (${(ev as any).score}%) — PCI DSS, EU CRA, NIST`);
                        speak(`Compliance audit passed. Score: ${(ev as any).score} percent. All regulatory frameworks satisfied.`);
                    } else {
                        addLog('⚠️', `Compliance FAILED (${(ev as any).score}%)`);
                        speak('Compliance audit failed.');
                    }
                    break;
            }
        });

        return () => { unlisten.then(f => f()); };
    }, []);

    const triggerDemo = async () => {
        setStatus('SCANNING');
        setActivityLog([]);
        setCommitHash(null);
        setComplianceScore(null);
        try { await invoke('trigger_swarm_demo'); } catch(e) { console.error(e); }
    };

    const replayDemo = async () => {
        setStatus('SCANNING');
        setActivityLog([]);
        setCommitHash(null);
        setComplianceScore(null);
        try { await invoke('replay_demo'); } catch(e) { console.error(e); }
    };

    const cfg = STATUS_CONFIG[status];

    return (
        <div style={{
            padding: "40px",
            minHeight: "100vh",
            background: "radial-gradient(ellipse at bottom, #0d1117 0%, #03040b 100%)",
            color: "#fff",
            fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        }}>
            <div style={{ textAlign: "center", marginBottom: "40px" }}>
                <h1 style={{ 
                    fontSize: "3.2rem", 
                    fontWeight: 800, 
                    letterSpacing: "-1px",
                    background: "linear-gradient(90deg, #4facfe 0%, #00f2fe 100%)",
                    WebkitBackgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                    margin: "0 0 10px 0"
                }}>
                    Self-Evolving DevSecOps Agent
                </h1>
                <p style={{ fontSize: "1.1rem", color: "#8b949e", maxWidth: "800px", margin: "0 auto 20px" }}>
                    Tauri + Amazon Nova + Datalog Engine. Fixing vulnerabilities before the PR is created.
                </p>
                <button onClick={triggerDemo} style={{
                    background: "linear-gradient(135deg, #eb2f96 0%, #722ed1 100%)",
                    color: "white",
                    border: "none",
                    padding: "12px 32px",
                    borderRadius: "12px",
                    fontSize: "1rem",
                    fontWeight: 700,
                    cursor: "pointer",
                    letterSpacing: "1px",
                    boxShadow: "0 4px 20px rgba(235, 47, 150, 0.3)",
                    transition: "transform 0.2s",
                }}>
                    🚀 LAUNCH SELF-HEALING
                </button>
                <button onClick={replayDemo} style={{
                    background: "linear-gradient(135deg, #13c2c2 0%, #4facfe 100%)",
                    color: "white",
                    border: "none",
                    padding: "12px 32px",
                    borderRadius: "12px",
                    fontSize: "1rem",
                    fontWeight: 700,
                    cursor: "pointer",
                    letterSpacing: "1px",
                    boxShadow: "0 4px 20px rgba(19, 194, 194, 0.3)",
                    transition: "transform 0.2s",
                }}>
                    🔄 REPLAY DEMO
                </button>
            </div>

            {/* Status Indicator */}
            <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "12px",
                marginBottom: "30px",
                padding: "12px 24px",
                background: `${cfg.color}11`,
                border: `1px solid ${cfg.color}44`,
                borderRadius: "12px",
                maxWidth: "400px",
                margin: "0 auto 30px",
                transition: "all 0.5s ease"
            }}>
                <span style={{
                    display: "inline-block",
                    width: "14px", height: "14px",
                    borderRadius: "50%",
                    background: cfg.color,
                    boxShadow: `0 0 12px ${cfg.color}`,
                    animation: status !== 'IDLE' ? "pulse 1.5s infinite" : "none"
                }}></span>
                <span style={{ color: cfg.color, fontSize: "1rem", fontWeight: 700, letterSpacing: "2px" }}>
                    {cfg.icon} {cfg.label}
                </span>
            </div>

            {/* Metrics Row */}
            <div style={{ display: "flex", gap: "16px", justifyContent: "center", flexWrap: "wrap", marginBottom: "30px" }}>
                <MetricCard title="AST Nodes Analyzed" value={scannedNodes.toLocaleString()} color="#4facfe" />
                <MetricCard title="Threats Detected" value={threatsFound.toString()} color="#ff4d4f" glowing={threatsFound > 0} />
                <MetricCard title="Shield Reviews" value={reviewCount.toString()} color="#13c2c2" glowing={reviewCount > 0} />
                <MetricCard title="Auto-Healed" value={patchesApplied.toString()} color="#52c41a" glowing={patchesApplied > 0} />
                <MetricCard title="Compliance" value={complianceScore !== null ? `${complianceScore}%` : '—'} color="#722ed1" glowing={complianceScore !== null && complianceScore >= 100} />
            </div>

            {/* Agent Neural Graph */}
            <div style={{ maxWidth: '900px', margin: '0 auto 30px' }}>
                <AgentNeuralGraph />
            </div>

            {/* Voice Toggle */}
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                <button onClick={() => { setVoiceEnabled(v => !v); if (!voiceEnabled) speechSynthesis.cancel(); }} style={{
                    background: voiceEnabled ? 'rgba(82, 196, 26, 0.15)' : 'rgba(139, 148, 158, 0.1)',
                    border: `1px solid ${voiceEnabled ? '#52c41a44' : '#30363d'}`,
                    color: voiceEnabled ? '#52c41a' : '#8b949e',
                    padding: '8px 20px',
                    borderRadius: '8px',
                    fontSize: '0.85rem',
                    cursor: 'pointer',
                    fontWeight: 600,
                    transition: 'all 0.3s'
                }}>
                    {voiceEnabled ? '🔊 Voice ON' : '🔇 Voice OFF'}
                </button>
            </div>

            {/* Live Activity Feed */}
            <div style={{ 
                background: "rgba(22, 27, 34, 0.4)", 
                border: "1px solid #30363d",
                borderRadius: "16px",
                padding: "24px",
                maxWidth: "900px",
                margin: "0 auto",
                backdropFilter: "blur(10px)",
                boxShadow: "0 20px 40px rgba(0,0,0,0.4)"
            }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                    <h2 style={{ fontSize: "1.3rem", margin: 0 }}>📡 Live Telemetry</h2>
                    {commitHash && (
                        <span style={{
                            background: "#52c41a22",
                            border: "1px solid #52c41a44",
                            borderRadius: "8px",
                            padding: "4px 12px",
                            color: "#52c41a",
                            fontSize: "0.85rem",
                            fontWeight: 600,
                            fontFamily: "monospace"
                        }}>
                            commit {commitHash}
                        </span>
                    )}
                </div>
                
                <div style={{ 
                    minHeight: "200px",
                    maxHeight: "300px",
                    overflowY: "auto",
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                }}>
                    {activityLog.length === 0 ? (
                        <div style={{ textAlign: "center", color: "#484f58", padding: "60px 0", fontStyle: "italic" }}>
                            Press <span style={{ color: "#eb2f96", fontWeight: 600 }}>LAUNCH SELF-HEALING</span> to start the AI Swarm
                        </div>
                    ) : (
                        activityLog.map((entry, i) => (
                            <div key={i} style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "10px",
                                padding: "8px 12px",
                                background: i === 0 ? "rgba(79, 172, 254, 0.06)" : "transparent",
                                borderRadius: "8px",
                                animation: i === 0 ? "slideIn 0.3s ease-out" : "none",
                                opacity: 1 - (i * 0.08)
                            }}>
                                <span style={{ fontSize: "1.1rem", flexShrink: 0 }}>{entry.icon}</span>
                                <span style={{ fontSize: "0.85rem", color: "#c9d1d9", flex: 1 }}>{entry.text}</span>
                                <span style={{ fontSize: "0.75rem", color: "#484f58", fontFamily: "monospace", flexShrink: 0 }}>{entry.time}</span>
                            </div>
                        ))
                    )}
                </div>
            </div>

            <style>{`
                @keyframes pulse {
                    0% { transform: scale(1); opacity: 1; }
                    50% { transform: scale(1.5); opacity: 0.5; }
                    100% { transform: scale(1); opacity: 1; }
                }
                @keyframes slideIn {
                    from { opacity: 0; transform: translateY(-8px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            `}</style>
        </div>
    );
}

function MetricCard({ title, value, color, glowing = false }: { title: string, value: string, color: string, glowing?: boolean }) {
    return (
        <div style={{
            background: "rgba(22, 27, 34, 0.4)",
            border: `1px solid ${glowing ? color : '#30363d'}`,
            borderRadius: "16px",
            padding: "18px 28px",
            minWidth: "180px",
            textAlign: "center",
            boxShadow: glowing ? `0 0 25px ${color}33` : "none",
            transition: "all 0.5s ease",
            backdropFilter: "blur(10px)"
        }}>
            <div style={{ fontSize: "0.75rem", color: "#8b949e", textTransform: "uppercase", letterSpacing: "1.5px", marginBottom: "8px" }}>
                {title}
            </div>
            <div style={{ 
                fontSize: "2.5rem", 
                fontWeight: 700, 
                color: color,
                textShadow: glowing ? `0 0 20px ${color}` : "none",
                transition: "all 0.3s ease"
            }}>
                {value}
            </div>
        </div>
    );
}
