import { useState, useEffect } from 'react';
import { listen, Event } from '@tauri-apps/api/event';

const LOOP_STAGES = [
    "PreHook",
    "ContextAssembly",
    "BuildPrompt",
    "LLMProvider",
    "ParseResponse",
    "ExecuteTool",
    "ProvideToolResult",
    "FinalAnswer",
    "PostHook"
];

// Combine LLMProvider to be visited twice if need be, but for a linear visualizer 9 nodes is better.
// ZeroClaw diagram: PreHook -> ContextAssembly -> BuildPrompt -> LLMProvider -> ParseResponse -> ExecuteTool -> ProvideToolResult -> (Loop back to LLMProvider) -> FinalAnswer -> PostHook

type AgentStateMap = Record<string, {
    currentState: string;
    details: string;
    lastUpdated: number;
}>;

export default function AgentLoopTracker() {
    const [agentStates, setAgentStates] = useState<AgentStateMap>({});

    useEffect(() => {
        const unlisten = listen<any>('swarm-event', (event: Event<any>) => {
            const ev = event.payload;
            if (ev.type === "AgentStateChanged") {
                setAgentStates(prev => ({
                    ...prev,
                    [ev.agent_id]: {
                        currentState: ev.state,
                        details: ev.details,
                        lastUpdated: Date.now()
                    }
                }));
            }
        });

        return () => {
            unlisten.then(f => f());
        };
    }, []);

    // Helper to get active agents (updated in last 10 seconds)
    const activeAgents = Object.entries(agentStates).filter(
        ([, state]) => Date.now() - state.lastUpdated < 10000
    );

    if (activeAgents.length === 0) {
        return (
            <div className="agent-loop-tracker empty">
                <p>Waiting for Agent reasoning loop activity...</p>
                <style>{`
                    .agent-loop-tracker.empty {
                        padding: 20px;
                        text-align: center;
                        color: #555;
                        font-family: monospace;
                        background: #0d1117;
                        border-radius: 8px;
                        border: 1px dashed #30363d;
                        margin-top: 15px;
                    }
                `}</style>
            </div>
        );
    }

    return (
        <div className="agent-loop-tracker">
            <h3 className="tracker-title">🧠 AI Agent Reasoning Engines (Live View)</h3>
            <div className="active-agents-list">
                {activeAgents.map(([agentId, state]) => (
                    <div key={agentId} className="agent-loop-row">
                        <div className="agent-loop-header">
                            <span className="agent-id-badge">{agentId}</span>
                            <span className="agent-current-details">{state.details}</span>
                        </div>
                        <div className="loop-pipeline">
                            {LOOP_STAGES.map((stage, idx) => {
                                const isActive = state.currentState === stage;
                                const isPassed = LOOP_STAGES.indexOf(state.currentState) > idx;
                                
                                let nodeClass = "loop-node";
                                if (isActive) nodeClass += " active";
                                else if (isPassed) nodeClass += " passed";

                                return (
                                    <div key={stage} className="loop-stage-wrapper">
                                        <div className={nodeClass}>
                                            <span className="node-dot"></span>
                                            <span className="node-label">{stage}</span>
                                        </div>
                                        {idx < LOOP_STAGES.length - 1 && (
                                            <div className={`loop-connector ${isPassed ? 'passed' : ''}`}></div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                ))}
            </div>

            <style>{`
                .agent-loop-tracker {
                    background: #0d1117;
                    border: 1px solid #21262d;
                    border-radius: 8px;
                    padding: 16px;
                    margin-top: 20px;
                }
                .tracker-title {
                    margin: 0 0 16px 0;
                    font-size: 0.9rem;
                    color: #8b949e;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                .active-agents-list {
                    display: flex;
                    flex-direction: column;
                    gap: 20px;
                }
                .agent-loop-row {
                    background: #161b22;
                    border-radius: 6px;
                    padding: 12px 16px;
                    border-left: 3px solid #79c0ff;
                }
                .agent-loop-header {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    margin-bottom: 12px;
                }
                .agent-id-badge {
                    background: #79c0ff22;
                    color: #79c0ff;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 0.8rem;
                    font-weight: 600;
                    border: 1px solid #79c0ff44;
                }
                .agent-current-details {
                    color: #c9d1d9;
                    font-size: 0.85rem;
                    font-family: monospace;
                }
                .loop-pipeline {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    width: 100%;
                    overflow-x: auto;
                    padding: 10px 0;
                }
                .loop-stage-wrapper {
                    display: flex;
                    align-items: center;
                    flex: 1;
                }
                .loop-stage-wrapper:last-child {
                    flex: 0;
                }
                .loop-node {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 6px;
                    position: relative;
                    z-index: 2;
                }
                .node-dot {
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    background: #21262d;
                    border: 2px solid #30363d;
                    transition: all 0.3s ease;
                }
                .node-label {
                    font-size: 0.65rem;
                    color: #8b949e;
                    position: absolute;
                    top: 20px;
                    white-space: nowrap;
                    font-weight: 500;
                    transition: color 0.3s ease;
                }
                .loop-node.passed .node-dot {
                    background: #2ea043;
                    border-color: #2ea043;
                }
                .loop-node.passed .node-label {
                    color: #2ea043;
                }
                .loop-node.active .node-dot {
                    background: #79c0ff;
                    border-color: #79c0ff;
                    box-shadow: 0 0 10px #79c0ff, 0 0 20px #79c0ff;
                    animation: pulse 1.5s infinite;
                }
                .loop-node.active .node-label {
                    color: #79c0ff;
                    font-weight: bold;
                }
                .loop-connector {
                    flex: 1;
                    height: 2px;
                    background: #30363d;
                    margin: 0 4px;
                    transform: translateY(-9px);
                    transition: background 0.3s ease;
                }
                .loop-connector.passed {
                    background: #2ea043;
                }
                @keyframes pulse {
                    0% { transform: scale(1); opacity: 1; }
                    50% { transform: scale(1.3); opacity: 0.8; }
                    100% { transform: scale(1); opacity: 1; }
                }
            `}</style>
        </div>
    );
}
