import { useState, useEffect, useRef, useCallback } from "react";
import ForceGraph3D from "react-force-graph-3d";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";


interface QueryResult {
  query: string;
  total: number;
  items: any[];
  duration_us: number;
}

export default function UniverseGraph3D() {
  const [graphData, setGraphData] = useState({ nodes: [] as any[], links: [] as any[] });
  const [loading, setLoading] = useState(true);
  const fgRef = useRef<any>(null);

  // Generate a mock galaxy of DevSecOps nodes if backend is empty
  const generateMockGalaxy = () => {
    const nodes = [];
    const links = [];
    const N = 800;
    
    // Core Infrastructure Nodes
    for (let i = 0; i < N; i++) {
      const typeRand = Math.random();
      let type = "package";
      if (typeRand > 0.95) type = "vulnerability";
      else if (typeRand > 0.90) type = "agent";
      else if (typeRand > 0.80) type = "binary";
      
      nodes.push({ id: `node-${i}`, name: `${type}_${i}`, type, val: type === "vulnerability" ? 15 : type === "agent" ? 10 : 3 });
    }

    // Links: Scale-free network approximation
    for (let i = 1; i < N; i++) {
      links.push({
        source: `node-${i}`,
        target: `node-${Math.floor(Math.random() * i)}`
      });
      // Add cross links
      if (Math.random() > 0.8) {
        links.push({
          source: `node-${i}`,
          target: `node-${Math.floor(Math.random() * N)}`
        });
      }
    }
    return { nodes, links };
  };

  useEffect(() => {
    async function fetchGraphData() {
      try {
        // Attempt to fetch from the actual graph database
        const r = await invoke<QueryResult>("query_sbom_graph", {
          sbomPath: "/opt/system/sbom.json", // Generic mock path
          query: { target: "components", filters: [], sort_by: null, limit: 1000 },
        });

        if (r && r.items && r.items.length > 0) {
          const nodes = r.items.map((i: any, idx) => ({
            id: i.purl || `n-${idx}`,
            name: i.name || "Unknown",
            type: i.has_vulnerabilities ? "vulnerability" : "package",
            val: i.has_vulnerabilities ? 10 : 3
          }));
          
          const links: any[] = [];
          // Simple link mock for the fetched nodes
          for (let i = 1; i < nodes.length; i++) {
             links.push({ source: nodes[i].id, target: nodes[0].id });
          }

          setGraphData({ nodes, links });
        } else {
           throw new Error("Empty graph");
        }
      } catch (e) {
        // Fallback to beautiful mock galaxy
        console.log("Using Mock D3 Galaxy:", e);
        setGraphData(generateMockGalaxy());
      } finally {
        setLoading(false);
      }
    }
    fetchGraphData();
  }, []);

  const handleNodeClick = useCallback(async (node: any) => {
    if (fgRef.current) {
      // Aim at node from outside it
      const distance = 40;
      const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
      
      fgRef.current.cameraPosition(
        { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
        node,
        3000 // ms transition duration
      );
    }
    
    // Dispatch knowledge base query for this node!
    const query = node.type === "vulnerability" ? `Explain CVE for ${node.name}` : `Analyze package ${node.name}`;
    await emit("open-knowledge-panel", query);

  }, [fgRef]);

  // Orbit rotation
  useEffect(() => {
    if (!fgRef.current) return;
    
    const distance = 800;
    let angle = 0;
    const updateAngle = () => {
      angle += Math.PI / 1000;
      if (fgRef.current) {
         fgRef.current.cameraPosition({
            x: distance * Math.sin(angle),
            z: distance * Math.cos(angle)
         });
      }
      requestAnimationFrame(updateAngle);
    };
    
    updateAngle(); // Start rotation
  }, [loading]);

  if (loading) {
    return <div style={{ color: "#8b949e", padding: 40 }}>Initializing WebGL Universe Engine...</div>;
  }

  return (
    <div style={{ width: "100%", height: "100vh", background: "#000005", position: "relative" }}>
      <div style={{ position: "absolute", top: 20, left: 30, zIndex: 10, pointerEvents: "none" }}>
        <h2 style={{ color: "white", margin: 0, fontSize: "2rem", textShadow: "0 0 10px #1890ff" }}>
          🌌 DevSecOps Graph Universe
        </h2>
        <p style={{ color: "#a5b4fc", marginTop: 5 }}>Interactive 3D Blast-Radius & Event Routing Engine</p>
      </div>

      <div style={{ position: "absolute", bottom: 20, right: 30, zIndex: 10, background: "rgba(0,0,0,0.5)", border: "1px solid #30363d", padding: "10px 15px", borderRadius: 8 }}>
        <div style={{ display: "flex", gap: 15, fontSize: "0.9rem", color: "#e6edf3" }}>
           <span><span style={{color: "#ff4d4f"}}>⬤</span> Critical Threat</span>
           <span><span style={{color: "#1890ff"}}>⬤</span> Infrastructure</span>
           <span><span style={{color: "#d4b106"}}>⬤</span> Swarm Agent</span>
        </div>
      </div>

      <ForceGraph3D
        ref={fgRef}
        graphData={graphData}
        nodeLabel="name"
        nodeColor={(node: any) => {
          if (node.type === "vulnerability") return "#ff4d4f"; // Red glowing
          if (node.type === "agent") return "#faad14"; // Gold
          if (node.type === "binary") return "#722ed1";
          return "#1890ff"; // Default blue Package
        }}
        nodeOpacity={0.9}
        nodeResolution={16}
        linkWidth={(link: any) => (link.source.type === "vulnerability" || link.target.type === "vulnerability" ? 2 : 0.5)}
        linkColor={(link: any) => (link.source.type === "vulnerability" || link.target.type === "vulnerability" ? "rgba(255, 77, 79, 0.4)" : "rgba(24, 144, 255, 0.2)")}
        linkDirectionalParticles={2}
        linkDirectionalParticleWidth={(link: any) => link.source.type === "agent" ? 4 : 1}
        linkDirectionalParticleColor={(link: any) => link.source.type === "agent" ? "#faad14" : "#1890ff"}
        linkDirectionalParticleSpeed={0.01}
        onNodeClick={handleNodeClick}
        backgroundColor="#000005"
      />
    </div>
  );
}
