import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface McpToolDef {
    name: string;
    description?: string;
    inputSchema: any;
}

export default function McpServersPanel() {
    const [serverName, setServerName] = useState('');
    const [command, setCommand] = useState('');
    const [args, setArgs] = useState('');
    
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [registeredServers, setRegisteredServers] = useState<{name: string, command: string, tools: McpToolDef[]}[]>([]);

    const handleRegister = async () => {
        if (!serverName || !command) return;
        setLoading(true);
        setError(null);
        
        try {
            // Split args by space for simplicity, keeping quoted strings together ideally, but split(' ') is okay for basic usage
            const parsedArgs = args.split(' ').filter(a => a.trim().length > 0);
            
            const tools: McpToolDef[] = await invoke('engine_register_mcp_server', {
                name: serverName,
                command: command,
                args: parsedArgs
            });
            
            setRegisteredServers(prev => [...prev, { name: serverName, command: `${command} ${args}`, tools }]);
            setServerName('');
            setCommand('');
            setArgs('');
        } catch (err: any) {
            console.error("Failed to register MCP server:", err);
            setError(err.toString());
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: '24px', maxWidth: '1000px', margin: '0 auto', color: '#fff' }}>
            <h2 style={{ fontSize: '24px', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                🔌 Model Context Protocol (MCP) Servers
            </h2>
            <p style={{ color: '#aaa', marginBottom: '24px' }}>
                Connect the ZeroClaw DevSecOps Swarm to external tools (GitHub, Jira, SQLite, FileSystem) via standard MCP over Stdio.
            </p>

            <div style={{ background: '#1e1e1e', padding: '24px', borderRadius: '8px', border: '1px solid #333', marginBottom: '32px' }}>
                <h3 style={{ fontSize: '16px', marginBottom: '16px', color: '#4fc3f7' }}>Register Local Server</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr', gap: '12px', marginBottom: '16px' }}>
                    <div>
                        <label style={{ display: 'block', fontSize: '12px', color: '#888', marginBottom: '4px' }}>Server Alias (e.g. github)</label>
                        <input 
                            type="text" 
                            style={{ width: '100%', padding: '8px', background: '#252526', border: '1px solid #444', color: '#fff', borderRadius: '4px' }}
                            value={serverName}
                            placeholder="my-server"
                            onChange={e => setServerName(e.target.value)}
                        />
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '12px', color: '#888', marginBottom: '4px' }}>Command (e.g. npx)</label>
                        <input 
                            type="text" 
                            style={{ width: '100%', padding: '8px', background: '#252526', border: '1px solid #444', color: '#fff', borderRadius: '4px' }}
                            value={command}
                            placeholder="npx"
                            onChange={e => setCommand(e.target.value)}
                        />
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '12px', color: '#888', marginBottom: '4px' }}>Arguments</label>
                        <input 
                            type="text" 
                            style={{ width: '100%', padding: '8px', background: '#252526', border: '1px solid #444', color: '#fff', borderRadius: '4px' }}
                            value={args}
                            placeholder="-y @modelcontextprotocol/server-sqlite --db /tmp/test.db"
                            onChange={e => setArgs(e.target.value)}
                        />
                    </div>
                </div>
                
                {error && <div style={{ background: '#3a1919', color: '#ff4d4f', padding: '12px', borderRadius: '4px', marginBottom: '16px', fontSize: '13px' }}>
                    ⚠️ {error}
                </div>}

                <button 
                    style={{ background: '#177ddc', color: '#fff', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 600, opacity: loading ? 0.7 : 1 }}
                    onClick={handleRegister}
                    disabled={loading}
                >
                    {loading ? 'Connecting & Handshaking...' : 'Register Transports'}
                </button>
            </div>

            <div>
                <h3 style={{ fontSize: '16px', marginBottom: '16px', color: '#fff' }}>Connected Servers ({registeredServers.length})</h3>
                {registeredServers.length === 0 && (
                    <div style={{ padding: '32px', textAlign: 'center', background: '#1e1e1e', borderRadius: '8px', border: '1px dashed #444', color: '#666' }}>
                        No MCP servers connected yet.
                    </div>
                )}
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {registeredServers.map((server, idx) => (
                        <div key={idx} style={{ background: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', overflow: 'hidden' }}>
                            <div style={{ padding: '12px 16px', borderBottom: '1px solid #333', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#252526' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <span style={{ color: '#52c41a' }}>🟢</span>
                                    <span style={{ fontWeight: 600, fontSize: '15px' }}>{server.name}</span>
                                    <span style={{ color: '#666', fontSize: '12px', fontFamily: 'monospace' }}>{server.command}</span>
                                </div>
                                <div style={{ fontSize: '12px', background: '#177ddc33', color: '#4fc3f7', padding: '2px 8px', borderRadius: '12px' }}>
                                    {server.tools.length} Tools Discovered
                                </div>
                            </div>
                            
                            <div style={{ padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '12px' }}>
                                {server.tools.map((tool, tidx) => (
                                    <div key={tidx} style={{ background: '#141414', padding: '12px', borderRadius: '6px', border: '1px solid #2a2a2a' }}>
                                        <div style={{ color: '#e8e8e8', fontWeight: 500, fontFamily: 'monospace', marginBottom: '8px' }}>{tool.name}</div>
                                        {tool.description && <div style={{ color: '#888', fontSize: '13px', marginBottom: '12px', lineHeight: 1.4 }}>{tool.description}</div>}
                                        <div style={{ fontSize: '11px', color: '#555', fontFamily: 'monospace', whiteSpace: 'pre-wrap', background: '#000', padding: '8px', borderRadius: '4px' }}>
                                            {JSON.stringify(tool.inputSchema, null, 2)}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
