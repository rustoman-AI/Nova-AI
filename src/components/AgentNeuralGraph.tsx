import { useState, useEffect, useRef } from 'react';
import { listen, Event } from '@tauri-apps/api/event';

type AgentNode = {
    id: string;
    label: string;
    x: number;
    y: number;
    color: string;
    icon: string;
    active: boolean;
    pulseIntensity: number;
};

type MessageBeam = {
    id: number;
    from: string;
    to: string;
    color: string;
    progress: number;
    label: string;
};

const AGENTS: AgentNode[] = [
    { id: 'threat',     label: 'ThreatIntel',    x: 100, y: 150, color: '#ff4d4f', icon: '🔍', active: false, pulseIntensity: 0 },
    { id: 'patch',      label: 'PatchAgent',     x: 350, y: 80,  color: '#eb2f96', icon: '⚙️', active: false, pulseIntensity: 0 },
    { id: 'reviewer',   label: 'NovaShield',     x: 600, y: 150, color: '#13c2c2', icon: '🛡️', active: false, pulseIntensity: 0 },
    { id: 'compliance', label: 'ComplianceBot',  x: 350, y: 280, color: '#722ed1', icon: '📋', active: false, pulseIntensity: 0 },
    { id: 'git',        label: 'GitAgent',       x: 600, y: 280, color: '#52c41a', icon: '💾', active: false, pulseIntensity: 0 },
];

const CONNECTIONS = [
    { from: 'threat', to: 'patch' },
    { from: 'patch', to: 'reviewer' },
    { from: 'reviewer', to: 'patch' },
    { from: 'patch', to: 'git' },
    { from: 'git', to: 'compliance' },
];

let beamCounter = 0;

export default function AgentNeuralGraph() {
    const [agents, setAgents] = useState<AgentNode[]>(AGENTS);
    const [beams, setBeams] = useState<MessageBeam[]>([]);
    const animRef = useRef<number>(0);

    // Animate beams
    useEffect(() => {
        const animate = () => {
            setBeams(prev => 
                prev
                    .map(b => ({ ...b, progress: b.progress + 0.02 }))
                    .filter(b => b.progress <= 1)
            );
            // Decay pulse intensity
            setAgents(prev => prev.map(a => ({
                ...a,
                pulseIntensity: Math.max(0, a.pulseIntensity - 0.01)
            })));
            animRef.current = requestAnimationFrame(animate);
        };
        animRef.current = requestAnimationFrame(animate);
        return () => { if (animRef.current) cancelAnimationFrame(animRef.current); };
    }, []);

    const fireBeam = (fromId: string, toId: string, color: string, label: string) => {
        setBeams(prev => [...prev, { id: beamCounter++, from: fromId, to: toId, color, progress: 0, label }]);
        activateAgent(fromId);
        setTimeout(() => activateAgent(toId), 800);
    };

    const activateAgent = (id: string) => {
        setAgents(prev => prev.map(a => a.id === id ? { ...a, active: true, pulseIntensity: 1 } : a));
        setTimeout(() => {
            setAgents(prev => prev.map(a => a.id === id ? { ...a, active: false } : a));
        }, 2000);
    };

    // Listen for swarm events
    useEffect(() => {
        const unlisten = listen<any>('swarm-event', (event: Event<any>) => {
            const ev = event.payload;
            switch (ev.type) {
                case 'ThreatDetected':
                    fireBeam('threat', 'patch', '#ff4d4f', 'THREAT');
                    break;
                case 'ReviewRequested':
                    fireBeam('patch', 'reviewer', '#eb2f96', 'PATCH');
                    break;
                case 'ReviewResult':
                    if (ev.approved) {
                        fireBeam('reviewer', 'patch', '#52c41a', 'APPROVED');
                    } else {
                        fireBeam('reviewer', 'patch', '#ff4d4f', 'REJECTED');
                    }
                    break;
                case 'PatchApplied':
                    fireBeam('patch', 'git', '#52c41a', 'COMMIT');
                    break;
                case 'ComplianceResult':
                    fireBeam('git', 'compliance', '#722ed1', 'AUDIT');
                    break;
            }
        });
        return () => { unlisten.then(f => f()); };
    }, []);

    const getAgent = (id: string) => agents.find(a => a.id === id)!;

    return (
        <div style={{ 
            background: 'rgba(13, 17, 23, 0.6)', 
            borderRadius: '16px', 
            border: '1px solid #21262d',
            padding: '20px',
            backdropFilter: 'blur(10px)'
        }}>
            <h3 style={{ color: '#8b949e', margin: '0 0 10px', fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '2px' }}>
                🧠 Agent Neural Graph
            </h3>
            <svg width="720" height="350" viewBox="0 0 720 350" style={{ width: '100%', height: 'auto' }}>
                <defs>
                    {agents.map(a => (
                        <radialGradient key={`glow-${a.id}`} id={`glow-${a.id}`}>
                            <stop offset="0%" stopColor={a.color} stopOpacity={0.3} />
                            <stop offset="100%" stopColor={a.color} stopOpacity={0} />
                        </radialGradient>
                    ))}
                    <filter id="blur-glow">
                        <feGaussianBlur stdDeviation="3" />
                    </filter>
                </defs>

                {/* Connection lines (static) */}
                {CONNECTIONS.map((c, i) => {
                    const from = getAgent(c.from);
                    const to = getAgent(c.to);
                    return (
                        <line key={i}
                            x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                            stroke="#21262d" strokeWidth={1.5} strokeDasharray="6 4"
                        />
                    );
                })}

                {/* Message beams (animated) */}
                {beams.map(beam => {
                    const from = getAgent(beam.from);
                    const to = getAgent(beam.to);
                    const cx = from.x + (to.x - from.x) * beam.progress;
                    const cy = from.y + (to.y - from.y) * beam.progress;
                    return (
                        <g key={beam.id}>
                            <line
                                x1={from.x} y1={from.y} x2={cx} y2={cy}
                                stroke={beam.color} strokeWidth={2} opacity={0.6}
                                filter="url(#blur-glow)"
                            />
                            <circle cx={cx} cy={cy} r={6} fill={beam.color} opacity={0.9}>
                                <animate attributeName="r" values="4;8;4" dur="0.5s" repeatCount="indefinite" />
                            </circle>
                            <text x={cx} y={cy - 12} textAnchor="middle" fill={beam.color} fontSize="9" fontWeight="bold" opacity={0.8}>
                                {beam.label}
                            </text>
                        </g>
                    );
                })}

                {/* Agent nodes */}
                {agents.map(a => (
                    <g key={a.id}>
                        {/* Glow circle */}
                        {a.pulseIntensity > 0 && (
                            <circle cx={a.x} cy={a.y} r={50} fill={`url(#glow-${a.id})`} opacity={a.pulseIntensity}>
                                <animate attributeName="r" values="40;55;40" dur="1.5s" repeatCount="indefinite" />
                            </circle>
                        )}
                        {/* Node circle */}
                        <circle cx={a.x} cy={a.y} r={28}
                            fill="#0d1117"
                            stroke={a.active ? a.color : '#30363d'}
                            strokeWidth={a.active ? 3 : 1.5}
                            style={{ transition: 'stroke 0.3s, stroke-width 0.3s' }}
                        />
                        {/* Icon */}
                        <text x={a.x} y={a.y + 5} textAnchor="middle" fontSize="20">{a.icon}</text>
                        {/* Label */}
                        <text x={a.x} y={a.y + 48} textAnchor="middle" fill="#8b949e" fontSize="11" fontWeight="600">
                            {a.label}
                        </text>
                        {/* Active indicator */}
                        {a.active && (
                            <circle cx={a.x + 20} cy={a.y - 20} r={5} fill={a.color}>
                                <animate attributeName="opacity" values="1;0.3;1" dur="0.8s" repeatCount="indefinite" />
                            </circle>
                        )}
                    </g>
                ))}
            </svg>
        </div>
    );
}
