import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import {
    ReactFlow,
    MiniMap,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    addEdge,
    MarkerType,
    Node,
    Edge
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

const initialNodes: Node[] = [];
const initialEdges: Edge[] = [];

type NodeState = "Unparsed" | "Parsed" | "Tested" | "Vulnerable" | "Quarantined" | "Healed" | "Verifying" | "CodeBroken" | "Reviewing" | "Rejected";

const getStateColor = (state: NodeState) => {
    switch (state) {
        case "Unparsed": return "#555";
        case "Parsed": return "#177ddc";
        case "Quarantined": return "#d4b106"; // Yellow/Orange
        case "Vulnerable": return "#a61d24"; // Red
        case "Verifying": return "#722ed1"; // Purple
        case "CodeBroken": return "#d4380d"; // Dark Orange
        case "Reviewing": return "#13c2c2"; // Teal (Cyan)
        case "Rejected": return "#eb2f96"; // Pink (Magenta)
        case "Healed": return "#237804"; // Green
        default: return "#222";
    }
};

export default function PulseGraph() {
    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

    // Auto-layout simple hack: position nodes linearly for demo

    useEffect(() => {
        const unlisten = listen("pulse-event", (event: any) => {
            const payload = event.payload;
            console.log("Pulse Event:", payload);

            if (payload.action === "NODE_SPAWNED") {
                setNodes(nds => {
                    if (nds.find(n => n.id === payload.node_id)) return nds;
                    return [...nds, {
                        id: payload.node_id,
                        position: { x: 250 + (nds.length * 200), y: 200 },
                        data: { label: `${payload.node_id}\n(${payload.initial_state})` },
                        style: {
                            background: getStateColor(payload.initial_state),
                            color: "#fff",
                            border: "1px solid #fff",
                            borderRadius: "8px",
                            padding: "10px",
                            boxShadow: "0 0 10px rgba(255,255,255,0.2)",
                            transition: "all 0.4s ease"
                        }
                    }];
                });
            } else if (payload.action === "STATE_TRANSITION") {
                setNodes(nds => nds.map(n => {
                    if (n.id === payload.node_id) {
                        return {
                            ...n,
                            data: { label: `${payload.node_id}\n(${payload.new_state})` },
                            style: {
                                ...n.style,
                                background: getStateColor(payload.new_state),
                                boxShadow: payload.new_state === "Healed"
                                    ? "0 0 25px rgba(35, 120, 4, 0.8)"
                                    : payload.new_state === "Quarantined"
                                        ? "0 0 25px rgba(212, 177, 6, 0.8)"
                                        : "0 0 10px rgba(255,255,255,0.2)"
                            }
                        };
                    }
                    return n;
                }));
            } else if (payload.action === "MESSAGE_SENT") {
                // Animate an edge!
                const edgeId = `e-${payload.from}-${payload.to}-${Date.now()}`;

                // Add the edge, make it animated
                setEdges(eds => addEdge({
                    id: edgeId,
                    source: payload.from,
                    target: payload.to,
                    animated: true,
                    label: payload.msg_type,
                    style: { stroke: "#177ddc", strokeWidth: 3 },
                    markerEnd: { type: MarkerType.ArrowClosed, color: "#177ddc" }
                }, eds));

                // Remove it after 2 seconds to simulate a "pulse" moving
                setTimeout(() => {
                    setEdges(eds => eds.filter(e => e.id !== edgeId));
                }, 2000);
            }
        });

        return () => {
            unlisten.then(f => f());
        };
    }, []);

    return (
        <div style={{ padding: 20, height: "80vh", maxWidth: 1000, margin: "auto" }}>
            <h2>🧬 The Pulse Graph (Live Unified Orchestration)</h2>
            <p>Real-time Actor Message Passing and Self-Healing Telemetry</p>
            <div style={{ width: "100%", height: "100%", background: "#0d1117", border: "1px solid #30363d", borderRadius: 8 }}>
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    colorMode="dark"
                    fitView
                >
                    <Controls />
                    <MiniMap nodeStrokeColor="#fff" nodeColor="#222" maskColor="rgba(0,0,0,0.8)" />
                    <Background color="#30363d" gap={16} />
                </ReactFlow>
            </div>

            <p style={{ marginTop: 20, fontSize: 13, color: '#888', textAlign: "center" }}>
                Legend:
                <span style={{ color: getStateColor("Unparsed"), margin: "0 10px" }}>⬤ Unparsed</span>
                <span style={{ color: getStateColor("Parsed"), margin: "0 10px" }}>⬤ Parsed</span>
                <span style={{ color: getStateColor("Quarantined"), margin: "0 10px" }}>⬤ Quarantined</span>
                <span style={{ color: getStateColor("Vulnerable"), margin: "0 10px" }}>⬤ Vulnerable</span>
                <span style={{ color: getStateColor("Verifying"), margin: "0 10px" }}>⬤ Verifying</span>
                <span style={{ color: getStateColor("CodeBroken"), margin: "0 10px" }}>⬤ Code Broken</span>
                <span style={{ color: getStateColor("Reviewing"), margin: "0 10px" }}>⬤ Reviewing</span>
                <span style={{ color: getStateColor("Rejected"), margin: "0 10px" }}>⬤ Rejected</span>
                <span style={{ color: getStateColor("Healed"), margin: "0 10px" }}>⬤ Healed</span>
            </p>
        </div>
    );
}
