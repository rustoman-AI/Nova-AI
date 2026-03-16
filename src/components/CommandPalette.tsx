import { useState, useEffect, useRef } from 'react';

type Command = {
    id: string;
    label: string;
    icon: string;
    category: string;
    action: () => void;
};

interface Props {
    onNavigate: (tab: string) => void;
}

export default function CommandPalette({ onNavigate }: Props) {
    const [open, setOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [selected, setSelected] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);

    const commands: Command[] = [
        // Navigation
        { id: 'nav-pitch', label: 'Agentic Dashboard', icon: '🚀', category: 'Navigate', action: () => onNavigate('pitch') },
        { id: 'nav-swarm', label: 'Swarm Activity', icon: '🐝', category: 'Navigate', action: () => onNavigate('swarmactivity') },
        { id: 'nav-attack', label: 'Attack Graph Paths', icon: '🔴', category: 'Navigate', action: () => onNavigate('novaattack') },
        { id: 'nav-pulse', label: 'Pulse Explorer', icon: '🧬', category: 'Navigate', action: () => onNavigate('pulsegraph') },
        { id: 'nav-sectools', label: 'Security Tools', icon: '🔧', category: 'Navigate', action: () => onNavigate('sectools') },
        { id: 'nav-slides', label: 'Pitch Slides', icon: '🎬', category: 'Navigate', action: () => onNavigate('pitchslides') },
        { id: 'nav-advanced', label: 'Advanced Features', icon: '🎯', category: 'Navigate', action: () => onNavigate('advanced') },
        { id: 'nav-deptree', label: 'Dependency Tree', icon: '🌳', category: 'Navigate', action: () => onNavigate('deptree') },
        { id: 'nav-exec', label: 'Executive Summary', icon: '📱', category: 'Navigate', action: () => onNavigate('execsummary') },
        { id: 'nav-attackpath', label: 'Attack-Path AI Engine', icon: '🔎', category: 'Navigate', action: () => onNavigate('attackpath') },
        // Actions
        { id: 'act-demo', label: 'Launch Self-Healing Demo', icon: '⚡', category: 'Actions', action: async () => {
            const { invoke } = await import('@tauri-apps/api/core');
            invoke('trigger_swarm_demo').catch(console.error);
        }},
        { id: 'act-replay', label: 'Replay Multi-Vuln Cascade', icon: '🔄', category: 'Actions', action: async () => {
            const { invoke } = await import('@tauri-apps/api/core');
            invoke('replay_demo').catch(console.error);
        }},
        { id: 'act-sbom', label: 'Export SBOM (CycloneDX)', icon: '📦', category: 'Actions', action: async () => {
            const { invoke } = await import('@tauri-apps/api/core');
            const sbom = await invoke<string>('generate_sbom');
            const blob = new Blob([sbom], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'sbom.cdx.json'; a.click();
        }},
        { id: 'act-cicd', label: 'Export CI/CD Pipeline', icon: '🔗', category: 'Actions', action: async () => {
            const { invoke } = await import('@tauri-apps/api/core');
            const yaml = await invoke<string>('generate_cicd_pipeline');
            const blob = new Blob([yaml], { type: 'text/yaml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'security.yml'; a.click();
        }},
        { id: 'act-readme', label: 'Generate SECURITY.md', icon: '📜', category: 'Actions', action: async () => {
            const { invoke } = await import('@tauri-apps/api/core');
            const md = await invoke<string>('generate_security_readme');
            const blob = new Blob([md], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'SECURITY.md'; a.click();
        }},
        { id: 'act-fullscreen', label: 'Toggle Fullscreen', icon: '⬛', category: 'Actions', action: () => {
            if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen();
        }},
    ];

    const filtered = commands.filter(c =>
        c.label.toLowerCase().includes(query.toLowerCase()) ||
        c.category.toLowerCase().includes(query.toLowerCase())
    );

    useEffect(() => {
        const handler = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                setOpen(prev => !prev);
                setQuery('');
                setSelected(0);
            }
            if (e.key === 'Escape') setOpen(false);
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, []);

    useEffect(() => {
        if (open) setTimeout(() => inputRef.current?.focus(), 50);
    }, [open]);

    const execute = (cmd: Command) => {
        setOpen(false);
        cmd.action();
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, filtered.length - 1)); }
        if (e.key === 'ArrowUp') { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
        if (e.key === 'Enter' && filtered[selected]) execute(filtered[selected]);
    };

    if (!open) return null;

    return (
        <div style={{
            position: 'fixed', inset: 0, zIndex: 99999,
            background: 'rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(4px)',
            display: 'flex', justifyContent: 'center', paddingTop: '15vh',
        }} onClick={() => setOpen(false)}>
            <div onClick={e => e.stopPropagation()} style={{
                width: '560px', maxHeight: '420px',
                background: '#161b22',
                border: '1px solid #30363d',
                borderRadius: '14px',
                boxShadow: '0 16px 70px rgba(0,0,0,0.5)',
                overflow: 'hidden',
                display: 'flex', flexDirection: 'column',
            }}>
                {/* Search */}
                <div style={{ padding: '12px 16px', borderBottom: '1px solid #21262d', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ color: '#8b949e', fontSize: '1.1rem' }}>🔍</span>
                    <input
                        ref={inputRef}
                        value={query}
                        onChange={e => { setQuery(e.target.value); setSelected(0); }}
                        onKeyDown={handleKeyDown}
                        placeholder="Type a command..."
                        style={{
                            flex: 1, background: 'transparent', border: 'none',
                            color: '#fff', fontSize: '1rem', outline: 'none',
                        }}
                    />
                    <kbd style={{
                        background: '#21262d', color: '#8b949e', padding: '2px 8px',
                        borderRadius: '4px', fontSize: '0.7rem', border: '1px solid #30363d'
                    }}>ESC</kbd>
                </div>
                {/* Results */}
                <div style={{ overflowY: 'auto', flex: 1, padding: '6px' }}>
                    {['Navigate', 'Actions'].map(cat => {
                        const items = filtered.filter(c => c.category === cat);
                        if (items.length === 0) return null;
                        return (
                            <div key={cat}>
                                <div style={{ padding: '6px 10px', fontSize: '0.7rem', color: '#484f58', textTransform: 'uppercase', letterSpacing: '1px' }}>
                                    {cat}
                                </div>
                                {items.map(cmd => {
                                    const idx = filtered.indexOf(cmd);
                                    return (
                                        <div key={cmd.id}
                                            onClick={() => execute(cmd)}
                                            onMouseEnter={() => setSelected(idx)}
                                            style={{
                                                display: 'flex', alignItems: 'center', gap: '10px',
                                                padding: '8px 12px', borderRadius: '8px', cursor: 'pointer',
                                                background: idx === selected ? 'rgba(79, 172, 254, 0.1)' : 'transparent',
                                                transition: 'background 0.1s',
                                            }}>
                                            <span style={{ fontSize: '1rem', width: '24px', textAlign: 'center' }}>{cmd.icon}</span>
                                            <span style={{ fontSize: '0.9rem', color: idx === selected ? '#fff' : '#c9d1d9' }}>{cmd.label}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        );
                    })}
                    {filtered.length === 0 && (
                        <div style={{ textAlign: 'center', padding: '30px', color: '#484f58', fontStyle: 'italic' }}>
                            No commands found
                        </div>
                    )}
                </div>
                <div style={{ borderTop: '1px solid #21262d', padding: '8px 16px', display: 'flex', gap: '16px', fontSize: '0.7rem', color: '#484f58' }}>
                    <span>↑↓ navigate</span>
                    <span>↵ select</span>
                    <span>esc close</span>
                </div>
            </div>
        </div>
    );
}
