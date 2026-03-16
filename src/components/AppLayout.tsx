import { useState, useCallback } from "react";
import CycloneDXRunner from "./CycloneDXRunner";
import { EStopButton } from "./EStopButton";
import WizardPanel from "./WizardPanel";
import JsonViewer from "./JsonViewer";
import VulnDashboard from "./VulnDashboard";
import DiffViewer from "./DiffViewer";
import FstecWizard from "./FstecWizard";
import PipelineHistory from "./PipelineHistory";
import CryptoPanel from "./CryptoPanel";
import AnalyzeDashboard from "./AnalyzeDashboard";
import AddFilesPanel from "./AddFilesPanel";
import SmartConvert from "./SmartConvert";
import MergeVisualizer from "./MergeVisualizer";
import DependencyGraph from "./DependencyGraph";
import LicenseIntelligence from "./LicenseIntelligence";
import CbomViewer from "./CbomViewer";
import AttestationDashboard from "./AttestationDashboard";
import ServicesPanel from "./ServicesPanel";
import BuildProvenance from "./BuildProvenance";
import EvidencePanel from "./EvidencePanel";
import BomHealthScore from "./BomHealthScore";
import BomCompare from "./BomCompare";
import VexViewer from "./VexViewer";
import ReportGenerator from "./ReportGenerator";
import StandardsViewer from "./StandardsViewer";
import BomGeneratorWizard from "./BomGeneratorWizard";
import TestScopeViewer from "./TestScopeViewer";
import ExternalRefsExplorer from "./ExternalRefsExplorer";
import PurlAnalyzer from "./PurlAnalyzer";
import SupplierIntelligence from "./SupplierIntelligence";
import DagPipelineBuilder from "./DagPipelineBuilder";
import SarifViewer from "./SarifViewer";
import RulesPanel from "./RulesPanel";
import DataStorePanel from "./DataStorePanel";
import TrivyScanPanel from "./TrivyScanPanel";
import CrossPipelinePanel from "./CrossPipelinePanel";
import ArchBrowserPanel from "./ArchBrowserPanel";
import UnifiedGraphPanel from "./UnifiedGraphPanel";
import TrustGraphPanel from "./TrustGraphPanel";
import TrustExecPanel from "./TrustExecPanel";
import GraphExplorerPanel from "./GraphExplorerPanel";
import SupplyChainPanel from "./SupplyChainPanel";
import RustSourcePanel from "./RustSourcePanel";
import SettingsPanel from "./SettingsPanel";
import AutoRemediationPanel from "./AutoRemediationPanel";
import IncidentPlaybooks from "./IncidentPlaybooks";
import HistoryDrawer, { type HistoryEntry } from "./HistoryDrawer";
import { ToastProvider } from "./Toasts";
import useKeyboard from "../hooks/useKeyboard";
import SwarmChat from "./SwarmChat";
import KnowledgePanel from "./KnowledgePanel";
import LiveAttackGraph from "./LiveAttackGraph";
import PulseGraph from "./PulseGraph";
import SwarmActivityModule from "./SwarmActivityModule";
import PitchDashboard from "./PitchDashboard";
import SecurityToolsPanel from "./SecurityToolsPanel";
import PitchSlides from "./PitchSlides";
import AdvancedFeaturesPanel from "./AdvancedFeaturesPanel";
import CommandPalette from "./CommandPalette";
import DependencyTreePanel from "./DependencyTreePanel";
import ExecutiveSummary from "./ExecutiveSummary";
import ExecutiveReport from "./ExecutiveReport";
import AttackPathEngine from "./AttackPathEngine";
import MCPServerHub from "./MCPServerHub";
import WasmPluginsPanel from "./WasmPluginsPanel";
import VectorRagPanel from "./VectorRagPanel";
import AuditLedger from "./AuditLedger";
import UniverseGraph3D from "./UniverseGraph3D";
import RedTeamExploits from "./RedTeamExploits";
import RuntimeDefensePanel from "./RuntimeDefensePanel";
import ThreatIntelPanel from "./ThreatIntelPanel";
import PostureTimelinePanel from "./PostureTimelinePanel";
import SocCommandCenter from "./SocCommandCenter";
import ImageForensicsPanel from "./ImageForensicsPanel";

type Tab = "pitch" | "runner" | "wizard" | "json" | "vuln" | "diff" | "nist_ssdf" | "runs" | "crypto" | "analyze" | "addfiles" | "convert" | "merge" | "depgraph" | "licenses" | "cbom" | "attestation" | "services" | "build" | "evidence" | "health" | "compare" | "vex" | "report" | "standards" | "bomgen" | "testscope" | "extrefs" | "purl" | "supplier" | "dagengine" | "sarif" | "rules" | "datastores" | "trivy" | "crosspipeline" | "archbrowser" | "unifiedgraph" | "universe" | "trustgraph" | "trustexec" | "graphexplorer" | "supplychain" | "rustsource" | "novaattack" | "pulsegraph" | "swarmactivity" | "sectools" | "pitchslides" | "advanced" | "deptree" | "execsummary" | "execreport" | "attackpath" | "mcpservers" | "wasmplugins" | "vectorrag" | "auditledger" | "remediation" | "playbooks" | "redteam" | "runtimedefense" | "threatintel" | "posturetimeline" | "soccenter" | "imageforensics";

interface SidebarGroup {
    id: string;
    label: string;
    icon: string;
    color: string;
    items: { id: Tab; label: string; icon: string }[];
}

const SIDEBAR: SidebarGroup[] = [
    {
        id: "nova_shield", label: "NOVA SHIELD", icon: "🛡️", color: "#f5222d",
        items: [
            { id: "novaattack", label: "Agentic Dashboard", icon: "🚀" },
            { id: "swarmactivity", label: "Swarm Activity", icon: "🐝" },
            { id: "attackpath", label: "Attack Graph Paths", icon: "🔴" },
            { id: "redteam", label: "Red Team Exploits", icon: "🎯" },
            { id: "pulsegraph", label: "Pulse Explorer", icon: "🚥" },
            { id: "sectools", label: "Security Tools", icon: "🔧" },
            { id: "pitchslides", label: "Pitch Slides", icon: "🎬" },
            { id: "advanced", label: "Advanced", icon: "🎯" },
            { id: "deptree", label: "Dependency Tree", icon: "🌳" },
            { id: "execsummary", label: "Executive Report", icon: "📱" },
            { id: "mcpservers", label: "MCP Servers", icon: "🔌" },
            { id: "wasmplugins", label: "WASM Plugins", icon: "⚡" },
            { id: "runtimedefense", label: "Runtime Defense", icon: "🐳" },
            { id: "threatintel", label: "Threat Intel", icon: "🌐" },
            { id: "soccenter", label: "SOC Center", icon: "🛡️" },
            { id: "imageforensics", label: "Image Forensics", icon: "🔬" },
        ],
    },
    {
        id: "source", label: "SOURCE", icon: "📝", color: "#eb2f96",
        items: [
            { id: "rustsource", label: "Code Intelligence", icon: "🦀" },
            { id: "supplychain", label: "Supply Chain", icon: "🔗" },
            { id: "graphexplorer", label: "Graph Explorer", icon: "🌐" },
            { id: "universe", label: "3D Universe", icon: "🌌" },
            { id: "archbrowser", label: "Architecture", icon: "🗺️" },
            { id: "analyze", label: "Analyze", icon: "🔬" },
            { id: "vectorrag", label: "Vector RAG", icon: "🧠" },
        ],
    },
    {
        id: "build", label: "BUILD", icon: "", color: "#fa8c16",
        items: [
            { id: "dagengine", label: "DAG Engine", icon: "⚙️" },
            { id: "build", label: "Provenance", icon: "🏗️" },
            { id: "crosspipeline", label: "Pipeline", icon: "" },
            { id: "evidence", label: "Evidence", icon: "🧬" },
            { id: "attestation", label: "Attestation", icon: "📜" },
            { id: "runs", label: "Runs", icon: "" },
        ],
    },
    {
        id: "supplychain", label: "SUPPLY CHAIN", icon: "", color: "#52c41a",
        items: [
            { id: "unifiedgraph", label: "SBOM Graph", icon: "🔮" },
            { id: "depgraph", label: "Dependencies", icon: "🕸️" },
            { id: "vuln", label: "Vulnerabilities", icon: "🛡️" },
            { id: "vex", label: "VEX", icon: "🔴" },
            { id: "licenses", label: "Licenses", icon: "🏷️" },
            { id: "purl", label: "PURL", icon: "" },
            { id: "supplier", label: "Suppliers", icon: "🏢" },
            { id: "cbom", label: "CBOM", icon: "" },
            { id: "crypto", label: "Crypto", icon: "" },
            { id: "trivy", label: "Trivy Scanner", icon: "🔍" },
        ],
    },
    {
        id: "governance", label: "GOVERNANCE", icon: "🏛️", color: "#722ed1",
        items: [
            { id: "trustgraph", label: "Trust Graph", icon: "⚡" },
            { id: "trustexec", label: "Compliance", icon: "🏛️" },
            { id: "auditledger", label: "Audit Trail", icon: "📜" },
            { id: "nist_ssdf", label: "NIST", icon: "🇷🇺" },
            { id: "rules", label: "Policies", icon: "📏" },
            { id: "health", label: "Health Score", icon: "" },
            { id: "posturetimeline", label: "Posture Timeline", icon: "📈" },
            { id: "standards", label: "Standards", icon: "📐" },
            { id: "execreport", label: "Executive Report", icon: "📊" },
            { id: "report", label: "Reports", icon: "" },
            { id: "sarif", label: "SARIF", icon: "📊" },
            { id: "remediation", label: "Auto-Remediation", icon: "🤖" },
            { id: "playbooks", label: "Incident Playbooks", icon: "📖" },
        ],
    },
    {
        id: "tools", label: "TOOLS", icon: "", color: "#1890ff",
        items: [
            { id: "runner", label: "CLI Runner", icon: "⚡" },
            { id: "wizard", label: "Wizard", icon: "🧙" },
            { id: "json", label: "JSON Viewer", icon: "📄" },
            { id: "convert", label: "Convert", icon: "" },
            { id: "merge", label: "Merge", icon: "🌳" },
            { id: "diff", label: "Diff", icon: "⇄" },
            { id: "compare", label: "Compare", icon: "⚖️" },
            { id: "addfiles", label: "Add Files", icon: "" },
            { id: "bomgen", label: "Generator", icon: "" },
            { id: "testscope", label: "Scope", icon: "🧪" },
            { id: "extrefs", label: "Ext Refs", icon: "" },
            { id: "services", label: "Services", icon: "" },
            { id: "datastores", label: "DataStores", icon: "🗄️" },
        ],
    },
];

export default function AppLayout() {
    const [activeTab, setActiveTab] = useState<Tab>("pitch");
    const navigateTo = (tab: string) => setActiveTab(tab as Tab);
    const [settingsOpen, setSettingsOpen] = useState(false);
    const [historyOpen, setHistoryOpen] = useState(false);
    const [history, setHistory] = useState<HistoryEntry[]>([]);
    const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

    const toggleGroup = useCallback((id: string) => {
        setCollapsed(prev => ({ ...prev, [id]: !prev[id] }));
    }, []);

    const addHistory = useCallback((entry: HistoryEntry) => {
        setHistory((prev) => [entry, ...prev].slice(0, 100));
    }, []);

    const clearHistory = useCallback(() => { setHistory([]); }, []);

    const handleRerun = useCallback((args: string) => {
        setHistoryOpen(false);
        setActiveTab("runner");
        window.dispatchEvent(new CustomEvent("cdx-rerun", { detail: args }));
    }, []);

    useKeyboard({
        onCloseOverlay: () => {
            if (settingsOpen) setSettingsOpen(false);
            else if (historyOpen) setHistoryOpen(false);
        },
        onSwitchTab: () => { },
    });

    // Find active group
    const activeGroup = SIDEBAR.find(g => g.items.some(i => i.id === activeTab));

    return (
        <ToastProvider>
            <div className="app-shell-v2">
                {/* Sidebar */}
                <nav className={`sidebar ${sidebarCollapsed ? "collapsed" : ""}`}>
                    <div className="sb-header">
                        <span className="sb-logo">🛡️</span>
                        {!sidebarCollapsed && <span className="sb-title">CycloneDX</span>}
                        <button className="sb-toggle" onClick={() => setSidebarCollapsed(!sidebarCollapsed)}>{sidebarCollapsed ? "→" : "←"}</button>
                    </div>

                    <div className="sb-groups">
                        {SIDEBAR.map(g => (
                            <div key={g.id} className="sb-group">
                                <button className={`sb-group-header ${activeGroup?.id === g.id ? "active" : ""}`}
                                    onClick={() => toggleGroup(g.id)} style={{ borderLeftColor: g.color }}>
                                    <span className="sb-group-icon">{g.icon}</span>
                                    {!sidebarCollapsed && <>
                                        <span className="sb-group-label">{g.label}</span>
                                        <span className="sb-chevron">{collapsed[g.id] ? "›" : "⌄"}</span>
                                    </>}
                                </button>
                                {!collapsed[g.id] && !sidebarCollapsed && (
                                    <div className="sb-items">
                                        {g.items.map(item => (
                                            <button key={item.id}
                                                className={`sb-item ${activeTab === item.id ? "active" : ""}`}
                                                onClick={() => setActiveTab(item.id)}
                                                style={activeTab === item.id ? { borderLeftColor: g.color, color: g.color } : {}}>
                                                <span className="sb-item-icon">{item.icon}</span>
                                                <span className="sb-item-label">{item.label}</span>
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>

                    <div className="sb-footer">
                        <button className="sb-footer-btn" onClick={() => setHistoryOpen(true)} title="History">🕐</button>
                        <button className="sb-footer-btn" onClick={() => setSettingsOpen(true)} title="Settings">⚙️</button>
                    </div>
                </nav>

                {/* Content */}
                <main className="main-content relative">
                    {/* Top breadcrumb */}
                    <div className="breadcrumb flex justify-between items-center w-full pr-4">
                        <div>
                            <span className="bc-stage" style={{ color: activeGroup?.color }}>{activeGroup?.icon} {activeGroup?.label}</span>
                            <span className="bc-sep">›</span>
                            <span className="bc-page">{SIDEBAR.flatMap(g => g.items).find(i => i.id === activeTab)?.icon} {SIDEBAR.flatMap(g => g.items).find(i => i.id === activeTab)?.label}</span>
                        </div>
                        <div className="flex items-center gap-4">
                            <EStopButton />
                        </div>
                    </div>

                    <div className="content-area">
                        {activeTab === "pitch" && <PitchDashboard />}
                        {activeTab === "runner" && <CycloneDXRunner onHistoryAdd={addHistory} />}
                        {activeTab === "wizard" && <WizardPanel />}
                        {activeTab === "json" && <JsonViewer />}
                        {activeTab === "vuln" && <VulnDashboard />}
                        {activeTab === "mcpservers" && <MCPServerHub />}
                        {activeTab === "wasmplugins" && <WasmPluginsPanel />}
                        {activeTab === "vectorrag" && <VectorRagPanel />}
                        {activeTab === "diff" && <DiffViewer />}
                        {activeTab === "nist_ssdf" && <FstecWizard />}
                        {activeTab === "runs" && <PipelineHistory />}
                        {activeTab === "crypto" && <CryptoPanel />}
                        {activeTab === "analyze" && <AnalyzeDashboard />}
                        {activeTab === "addfiles" && <AddFilesPanel />}
                        {activeTab === "convert" && <SmartConvert />}
                        {activeTab === "merge" && <MergeVisualizer />}
                        {activeTab === "depgraph" && <DependencyGraph />}
                        {activeTab === "licenses" && <LicenseIntelligence />}
                        {activeTab === "cbom" && <CbomViewer />}
                        {activeTab === "attestation" && <AttestationDashboard />}
                        {activeTab === "services" && <ServicesPanel />}
                        {activeTab === "build" && <BuildProvenance />}
                        {activeTab === "evidence" && <EvidencePanel />}
                        {activeTab === "health" && <BomHealthScore />}
                        {activeTab === "compare" && <BomCompare />}
                        {activeTab === "vex" && <VexViewer />}
                        {activeTab === "report" && <ReportGenerator />}
                        {activeTab === "standards" && <StandardsViewer />}
                        {activeTab === "bomgen" && <BomGeneratorWizard />}
                        {activeTab === "testscope" && <TestScopeViewer />}
                        {activeTab === "extrefs" && <ExternalRefsExplorer />}
                        {activeTab === "purl" && <PurlAnalyzer />}
                        {activeTab === "supplier" && <SupplierIntelligence />}
                        {activeTab === "dagengine" && <DagPipelineBuilder />}
                        {activeTab === "sarif" && <SarifViewer />}
                        {activeTab === "remediation" && <AutoRemediationPanel />}
                        {activeTab === "playbooks" && <IncidentPlaybooks />}
                        {activeTab === "redteam" && <RedTeamExploits />}
                        {activeTab === "runtimedefense" && <RuntimeDefensePanel />}
                        {activeTab === "threatintel" && <ThreatIntelPanel />}
                        {activeTab === "posturetimeline" && <PostureTimelinePanel />}
                        {activeTab === "soccenter" && <SocCommandCenter />}
                        {activeTab === "imageforensics" && <ImageForensicsPanel />}
                        {activeTab === "rules" && <RulesPanel />}
                        {activeTab === "datastores" && <DataStorePanel />}
                        {activeTab === "trivy" && <TrivyScanPanel />}
                        {activeTab === "crosspipeline" && <CrossPipelinePanel />}
                        {activeTab === "archbrowser" && <ArchBrowserPanel />}
                        {activeTab === "unifiedgraph" && <UnifiedGraphPanel />}
                        {activeTab === "universe" && <UniverseGraph3D />}
                        {activeTab === "trustgraph" && <TrustGraphPanel />}
                        {activeTab === "trustexec" && <TrustExecPanel />}
                        {activeTab === "auditledger" && <AuditLedger />}
                        {activeTab === "graphexplorer" && <GraphExplorerPanel />}
                        {activeTab === "supplychain" && <SupplyChainPanel />}
                        {activeTab === "rustsource" && <RustSourcePanel />}
                        {activeTab === "novaattack" && <LiveAttackGraph />}
                        {activeTab === "pulsegraph" && <PulseGraph />}
                        {activeTab === "swarmactivity" && <SwarmActivityModule />}
                        {activeTab === "sectools" && <SecurityToolsPanel />}
                        {activeTab === "pitchslides" && <PitchSlides />}
                        {activeTab === "advanced" && <AdvancedFeaturesPanel />}
                        {activeTab === "deptree" && <DependencyTreePanel />}
                        {activeTab === "execsummary" && <ExecutiveSummary />}
                        {activeTab === "execreport" && <ExecutiveReport />}
                        {activeTab === "attackpath" && <AttackPathEngine />}
                    </div>
                </main>

                {/* Overlays */}
                <SettingsPanel open={settingsOpen} onClose={() => setSettingsOpen(false)} />
                <HistoryDrawer open={historyOpen} onClose={() => setHistoryOpen(false)} entries={history} onRerun={handleRerun} onClear={clearHistory} />
                <CommandPalette onNavigate={navigateTo} />
            </div>

            <SwarmChat />
            <KnowledgePanel />

            <style>{`
                .app-shell-v2{display:flex;height:100vh;overflow:hidden;background:#0a0a16;color:#e0e0e0}
                /* Sidebar */
                .sidebar{width:220px;min-width:220px;background:#0e0e1a;border-right:1px solid #1a1a30;display:flex;flex-direction:column;transition:all .2s}
                .sidebar.collapsed{width:52px;min-width:52px}
                .sb-header{display:flex;align-items:center;gap:8px;padding:12px;border-bottom:1px solid #1a1a30;min-height:44px}
                .sb-logo{font-size:20px}
                .sb-title{font-size:13px;font-weight:700;color:#e0e0e0;white-space:nowrap}
                .sb-toggle{margin-left:auto;background:none;border:1px solid #2a2a4a;border-radius:4px;color:#666;cursor:pointer;font-size:11px;padding:2px 6px;transition:color .15s}
                .sb-toggle:hover{color:#e0e0e0}
                .sb-groups{flex:1;overflow-y:auto;padding:6px 0}
                .sb-group{margin-bottom:2px}
                .sb-group-header{display:flex;align-items:center;gap:8px;width:100%;padding:6px 12px;background:none;border:none;border-left:3px solid transparent;color:#8c8c8c;cursor:pointer;font-size:11px;text-transform:uppercase;letter-spacing:1px;transition:all .15s;text-align:left}
                .sb-group-header:hover{background:#ffffff06;color:#e0e0e0}
                .sb-group-header.active{color:#e0e0e0;background:#ffffff04}
                .sb-group-icon{font-size:14px;min-width:18px;text-align:center}
                .sb-group-label{flex:1;font-weight:600}
                .sb-chevron{font-size:12px;color:#555}
                .sb-items{padding:2px 0}
                .sb-item{display:flex;align-items:center;gap:8px;width:100%;padding:5px 12px 5px 28px;background:none;border:none;border-left:3px solid transparent;color:#666;cursor:pointer;font-size:12px;transition:all .12s;text-align:left}
                .sb-item:hover{background:#ffffff06;color:#b8b8cc}
                .sb-item.active{background:#ffffff08;color:#e0e0e0;font-weight:600}
                .sb-item-icon{font-size:13px;min-width:18px;text-align:center}
                .sb-item-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
                .sb-footer{display:flex;gap:4px;padding:8px 12px;border-top:1px solid #1a1a30;justify-content:center}
                .sb-footer-btn{background:none;border:1px solid #2a2a4a;border-radius:6px;padding:4px 8px;cursor:pointer;font-size:14px;transition:background .15s}
                .sb-footer-btn:hover{background:#ffffff0a}
                /* Main content */
                .main-content{flex:1;display:flex;flex-direction:column;overflow:hidden}
                .breadcrumb{display:flex;align-items:center;gap:8px;padding:8px 20px;border-bottom:1px solid #1a1a30;background:#0e0e1a;min-height:36px}
                .bc-stage{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px}
                .bc-sep{color:#333;font-size:14px}
                .bc-page{font-size:12px;color:#e0e0e0}
                .content-area{flex:1;overflow-y:auto;overflow-x:hidden}
            `}</style>
        </ToastProvider>
    );
}
