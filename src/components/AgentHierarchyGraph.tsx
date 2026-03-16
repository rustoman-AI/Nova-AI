import { useEffect } from 'react';
import {
  ReactFlow,
  useNodesState,
  useEdgesState,
  MarkerType,
  Background,
  Controls,
  Edge,
  Node,
  Panel
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { listen, Event } from '@tauri-apps/api/event';
import { SwarmEventPayload } from './SwarmActivityModule';

const initialNodes: Node[] = [
  { id: 'LeaderAgent', position: { x: 250, y: 50 }, data: { label: '👑 LeaderAgent (Orchestrator)' }, style: { background: '#13c2c2', color: '#fff', border: '2px solid #08979c', fontWeight: 'bold', padding: '10px 15px', borderRadius: '8px' } },
  { id: 'PatchAgent', position: { x: 50, y: 220 }, data: { label: '⚙️ PatchAgent' }, style: { background: '#eb2f96', color: '#fff', border: '2px solid #c41d7f', padding: '10px', borderRadius: '8px' } },
  { id: 'FuzzAgent', position: { x: 250, y: 220 }, data: { label: '🔀 FuzzAgent' }, style: { background: '#fa8c16', color: '#fff', border: '2px solid #d46b08', padding: '10px', borderRadius: '8px' } },
  { id: 'NovaShield', position: { x: 450, y: 220 }, data: { label: '🛡️ NovaShield' }, style: { background: '#52c41a', color: '#fff', border: '2px solid #389e0d', padding: '10px', borderRadius: '8px' } },
];

const initialEdges: Edge[] = [
    // Invisible structure edges to indicate hierarchy
    { id: 'e-L-P', source: 'LeaderAgent', target: 'PatchAgent', style: { stroke: '#30363d', strokeDasharray: '4 4' } },
    { id: 'e-L-F', source: 'LeaderAgent', target: 'FuzzAgent', style: { stroke: '#30363d', strokeDasharray: '4 4' } },
    { id: 'e-L-N', source: 'LeaderAgent', target: 'NovaShield', style: { stroke: '#30363d', strokeDasharray: '4 4' } },
];

export default function AgentHierarchyGraph() {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    const unlisten = listen<SwarmEventPayload>('swarm-event', (event: Event<SwarmEventPayload>) => {
      const ev = event.payload;
      if (ev.type === "TeamOrchestration") {
        const { source, destination, summary } = ev.payload;
        // Verify nodes exist
        const srcExists = initialNodes.some(n => n.id === source);
        const destExists = initialNodes.some(n => n.id === destination);
        
        if (srcExists && destExists) {
            const edgeId = `e-ipc-${source}-${destination}-${Date.now()}`;
            const newEdge: Edge = {
              id: edgeId,
              source,
              target: destination,
              animated: true,
              label: summary.length > 25 ? summary.substring(0, 25) + '...' : summary,
              style: { stroke: '#5cdbd3', strokeWidth: 3 },
              labelStyle: { fill: '#0df', fontWeight: 800, fontSize: 11, background: '#0a0a16' },
              labelBgBorderRadius: 4,
              labelBgPadding: [4, 4],
              labelBgStyle: { fill: '#0a0a16', stroke: '#13c2c2', strokeWidth: 1 },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#5cdbd3', width: 20, height: 20 },
            };
            
            // Add the new IPC animated edge
            setEdges((eds) => [...eds, newEdge]);
            
            // Remove the animated edge after 5 seconds to prevent clutter
            setTimeout(() => {
                setEdges((eds) => eds.filter(e => e.id !== edgeId));
            }, 5000);
        }
      }
    });

    return () => {
      unlisten.then(f => f());
    };
  }, [setEdges]);

  return (
    <div style={{ width: '100%', height: '100%', background: '#05050a', borderRadius: '0 0 8px 8px' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        colorMode="dark"
        minZoom={0.5}
        maxZoom={2}
      >
        <Background gap={16} size={1} color="#1a1a30" />
        <Controls />
        <Panel position="top-right" style={{ background: 'rgba(0,0,0,0.5)', padding: '5px 10px', borderRadius: '4px', fontSize: '11px', color: '#0df' }}>
          Live IPC Bus Monitoring Active
        </Panel>
      </ReactFlow>
    </div>
  );
}
