# Autonomous Graph-Driven DevSecOps Engine

> 5 paradigms: Erlang/OTP Actors + Datalog Reasoning + Multi-Agent AI + Reactive Graph + Self-Healing Pipeline

This document contains the core Mermaid diagrams for the pitch deck.

## 1. Unified DevSecOps Graph Strategy

```mermaid
graph TD
    classDef ai fill:#2a2a4a,stroke:#4facfe,stroke-width:2px,color:#fff
    classDef graph fill:#1a1a30,stroke:#eb2f96,stroke-width:2px,color:#fff
    classDef source fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#fff

    subgraph "Continuous Parsing"
        A[Git Source Code]:::source -->|rust-analyzer / tree-sitter| B(AST Graph)
        C[Cargo.toml / lock]:::source -->|CycloneDX| D(SBOM Graph)
    end

    subgraph "Knowledge Graphs"
        B :::graph --> E{Unified Meta-Graph}:::graph
        D :::graph --> E
        E --> F[Runtime Execution Data]
    end

    subgraph "Datalog Engine (SecQL)"
        E --> G[(Crepe DB)]:::graph
        G -->|FlowsTo, Tainted| H[Deep Vulnerability Tracing]
    end

    subgraph "Agentic Layer (Amazon Nova)"
        H --> I(Threat Intel Agent):::ai
        I --> J(Patch Generator Agent):::ai
        J --> K(Code Reviewer Agent):::ai
        K --> L(Compliance Agent):::ai
        L --> M(Git Agent):::ai
    end
```

## 2. Multi-Agent Swarm Self-Healing Loop (7 Agents)

```mermaid
sequenceDiagram
    participant IDB as Datalog Metagraph
    participant TI as Threat Intel Agent
    participant PA as Patch Agent
    participant CC as Cargo Check
    participant CR as Reviewer Agent
    participant CA as Compliance Agent
    participant TA as Test Agent
    participant FA as Fuzz Agent
    participant AP as AttackPath AI
    participant Git as Git Agent

    IDB->>TI: Trigger: Tainted Node Discovered
    TI->>PA: SwarmEvent::ThreatDetected (Node, Source)
    
    loop Self-Healing Core
        PA->>PA: Amazon Nova: Generates Secure Patch
        PA->>CC: Write code & Run Compiler
        alt Compiler Fails
            CC-->>PA: Rustc stderr
            PA->>PA: Amazon Nova: Fix syntax error
        else Compiler Succeeds
            PA->>CR: SwarmEvent::ReviewRequested
            CR->>CR: Amazon Nova: Security Audit
            alt Review Rejected
                CR-->>PA: SwarmEvent::ReviewResult (Critique)
            else Review Approved
                CR-->>CA: SwarmEvent::ReviewResult (Approved)
            end
        end
    end
    
    CA->>CA: Audit: PCI DSS, EU CRA, NIST
    CA->>TA: SwarmEvent::ComplianceResult (PASS)
    TA->>TA: Run unit + integration + e2e
    TA->>FA: SwarmEvent::TestPassed
    FA->>FA: 2048 mutations, 0 crashes
    FA->>AP: SwarmEvent::FuzzResult
    AP->>AP: Analyze exploit chains in MetaGraph
    AP->>Git: SwarmEvent::ExploitChainDetected (NEUTRALIZED)
    Git->>Git: Branch `nova-heal/cve` -> Commit
```

## 3. Actor Registry Architecture (7 Agents + Telemetry)

```mermaid
graph LR
    classDef actor fill:#161b22,stroke:#8b949e,color:#c9d1d9
    classDef bus fill:#1f6feb,stroke:#58a6ff,color:#fff

    Bus((SwarmBus<br/>mpsc::broadcast)):::bus

    TA[Threat Intel]:::actor <-->|Pub/Sub| Bus
    PA[Patch Agent]:::actor <-->|Pub/Sub| Bus
    RA[Reviewer Agent]:::actor <-->|Pub/Sub| Bus
    CA[Compliance Agent]:::actor <-->|Pub/Sub| Bus
    TSA[Test Agent]:::actor <-->|Pub/Sub| Bus
    FA[Fuzz Agent]:::actor <-->|Pub/Sub| Bus
    APA[AttackPath AI]:::actor <-->|Pub/Sub| Bus
    GA[Git Agent]:::actor <-->|Pub/Sub| Bus
    UI[Tauri Frontend]:::actor <-->|listen()| Bus

    %% Telemetry
    Bus -.->|Pulse UI Events| UI
```

## 4. Frontend Component Architecture (Phase 9–14)

```mermaid
graph TB
    classDef nova fill:#1a1a30,stroke:#eb2f96,stroke-width:2px,color:#fff
    classDef tool fill:#161b22,stroke:#4facfe,stroke-width:1px,color:#c9d1d9
    classDef overlay fill:#2a2a4a,stroke:#722ed1,stroke-width:1px,color:#fff

    subgraph "NOVA SHIELD — 11 Tabs"
        PD[🚀 PitchDashboard<br/>Live Telemetry + Neural Graph]:::nova
        SA[🐝 SwarmActivityModule<br/>Event Cards + Diff Viewer]:::nova
        AG[🔴 LiveAttackGraph<br/>Attack Path Visualization]:::nova
        PG[🧬 PulseGraph<br/>Actor Communication]:::nova
        ST[🔧 SecurityToolsPanel<br/>7 Sub-Tabs]:::tool
        PS[🎬 PitchSlides<br/>6-Slide Deck, Fullscreen]:::tool
        AFP[🎯 AdvancedFeaturesPanel<br/>5 Sub-Tabs]:::tool
        DTP[🌳 DependencyTreePanel<br/>Interactive Cargo Tree]:::tool
        ES[📱 ExecutiveSummary<br/>CTO Report]:::tool
    end

    subgraph "Global Overlays"
        CP[⌨️ CommandPalette<br/>Ctrl+K, 15+ Commands]:::overlay
    end

    subgraph "SecurityToolsPanel — 7 Tabs"
        SS[📈 Security Score Radar]
        NC[💬 Nova Chat]
        SB[📦 SBOM Export]
        CI[🔗 CI/CD Generator]
        HM[🗺️ Attack Heatmap]
        RM[📜 SECURITY.md]
        NT[🔔 Desktop Alerts]
    end

    subgraph "AdvancedFeaturesPanel — 5 Tabs"
        AP[⏱️ Agent Profiler]
        ML[🌐 Multi-Lang 6 Languages]
        TT[📊 Threat Timeline]
        AC[🏆 Achievements 8 Badges]
        LD[🎯 Live Demo Script]
    end

    ST --> SS & NC & SB & CI & HM & RM & NT
    AFP --> AP & ML & TT & AC & LD
```

## 5. Tauri Commands — Backend API (46 Commands)

```mermaid
graph LR
    classDef cmd fill:#161b22,stroke:#52c41a,stroke-width:1px,color:#c9d1d9

    subgraph "Original Commands (22)"
        C1[run_cyclonedx]:::cmd
        C2[run_external_tool]:::cmd
        C3[engine_execute]:::cmd
        C4[pipeline_create / list / get]:::cmd
        C5[export_report]:::cmd
    end

    subgraph "Nova Commands (Phase 1–8)"
        N1[trigger_swarm_demo]:::cmd
        N2[run_full_datalog]:::cmd
        N3[query_attack_paths]:::cmd
    end

    subgraph "Production Commands (Phase 9–14)"
        P1[replay_demo]:::cmd
        P2[scan_real_cves]:::cmd
        P3[generate_sbom]:::cmd
        P4[chat_with_nova]:::cmd
        P5[generate_cicd_pipeline]:::cmd
        P6[generate_security_readme]:::cmd
        P7[send_notification]:::cmd
    end
```

## 6. Multi-Vulnerability Cascade (Demo Scenario)

```mermaid
sequenceDiagram
    participant Demo as replay_demo
    participant TI as ThreatIntel
    participant PA as PatchAgent
    participant CR as Reviewer
    participant CA as Compliance
    participant Git as GitAgent

    Note over Demo: Vulnerability #1
    Demo->>TI: SQL Injection (CVE-2026-0002)
    TI->>PA: ThreatDetected
    PA->>CR: ReviewRequested
    CR->>CA: ReviewResult(Approved)
    CA->>Git: ComplianceResult(PASS)
    Git->>Git: PatchApplied (commit)

    Note over Demo: Vulnerability #2
    Demo->>TI: XSS (CVE-2026-0017)
    TI->>PA: ThreatDetected
    PA->>CR: ReviewRequested
    CR->>Git: ReviewResult(Approved) → Commit

    Note over Demo: Vulnerability #3
    Demo->>TI: OS Cmd Injection (CVE-2026-0031)
    TI->>PA: ThreatDetected
    PA->>CR: ReviewRequested
    CR->>Git: ReviewResult(Approved) → Commit
```

## 7. Hyperscale Architecture — Full Stack

```mermaid
graph TB
    classDef graph fill:#0d1117,stroke:#58a6ff,stroke-width:2px,color:#c9d1d9
    classDef meta fill:#161b22,stroke:#f0883e,stroke-width:2px,color:#f0883e
    classDef reason fill:#1a1a30,stroke:#eb2f96,stroke-width:2px,color:#eb2f96
    classDef bus fill:#1f6feb,stroke:#58a6ff,color:#fff
    classDef agent fill:#161b22,stroke:#4facfe,stroke-width:1px,color:#c9d1d9
    classDef git fill:#238636,stroke:#3fb950,stroke-width:2px,color:#fff

    subgraph "Layer 1: Graph-of-Graphs"
        AST["🌳 AST Graph<br/>syn parser"]:::graph
        SBOM["📦 SBOM Graph<br/>CycloneDX 1.5"]:::graph
        DEP["🔗 Dependency Graph<br/>Cargo.lock"]:::graph
        ATTACK["🔴 Attack Graph<br/>petgraph Dijkstra"]:::graph
        TRUST["🛡️ Trust Graph<br/>BFS propagation"]:::graph
        BUILD["⚙️ Build Graph<br/>Pipeline DAG"]:::graph
    end

    subgraph "Layer 2: Unified Reasoning"
        META["🧠 MetaGraph<br/>Graph-of-Graphs"]:::meta
        DATALOG["📐 Datalog Engine<br/>Crepe: FlowsTo, Tainted"]:::reason
        REASONING["🔎 Security Reasoning<br/>Exploit Path Search"]:::reason
    end

    subgraph "Layer 3: Event Bus"
        BUS(("⚡ SwarmBus<br/>broadcast::Sender<br/>9 SwarmEvent variants")):::bus
    end

    subgraph "Layer 4: Agent Swarm"
        TI["🔍 ThreatIntel"]:::agent
        PA["⚙️ PatchAgent"]:::agent
        CR["🛡️ Reviewer"]:::agent
        CA["📋 Compliance"]:::agent
        TA["🧪 TestAgent"]:::agent
        FA["🔀 FuzzAgent"]:::agent
        AP["🔎 AttackPathAI"]:::agent
    end

    subgraph "Layer 5: Integration"
        GIT["💾 Git Agent<br/>Auto-branch + Commit"]:::git
    end

    AST & SBOM & DEP & ATTACK & TRUST & BUILD --> META
    META --> DATALOG
    DATALOG --> REASONING
    REASONING --> BUS
    BUS <--> TI & PA & CR & CA & TA & FA & AP
    PA & CR & CA --> GIT
```

### Data Flow Pipeline

```
Codebase → AST Graph → MetaGraph → Datalog → Event Bus → Agent Swarm (8) → Exploit Simulation → Self-Healing Git Patch
```

## 8. Exploit Simulation Engine — Red Team vs Blue Team

```mermaid
graph LR
    classDef red fill:#1a0a0a,stroke:#ff4d4f,stroke-width:2px,color:#ff4d4f
    classDef blue fill:#0a0a1a,stroke:#4facfe,stroke-width:2px,color:#4facfe
    classDef green fill:#0a1a0a,stroke:#52c41a,stroke-width:2px,color:#52c41a

    subgraph "🔴 Red Team — Attacker"
        R1["🔍 Recon<br/>Scan endpoints"]:::red
        R2["💉 Exploit<br/>SQL Injection"]:::red
        R3["⬆️ Escalate<br/>Credential dump"]:::red
        R4["📤 Exfiltrate<br/>Data theft"]:::red
    end

    subgraph "🔵 Blue Team — Defender"
        B1["👁️ WAF<br/>Monitoring"]:::blue
        B2["🔍 ThreatIntel<br/>Detection"]:::blue
        B3["⚙️ PatchAgent<br/>Auto-fix"]:::blue
        B4["🛡️ NovaShield<br/>Patch deployed"]:::blue
    end

    R1 --> R2 --> R3 --> R4
    R2 -.->|detected| B2
    R3 -.->|race| B3
    R4 -.->|BLOCKED| B4

    B4 --> RESULT["✅ Defense Wins<br/>MTTR: 4.8s<br/>2/5 phases blocked"]:::green
```
