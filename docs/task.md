# Autonomous Graph-Driven DevSecOps Engine

> 5 paradigms: Erlang/OTP Actors + Datalog Reasoning + Multi-Agent AI + Reactive Graph + Self-Healing Pipeline
> ```
> Codebase → AST Graph → Attack Graph (Datalog) → Actor Runtime → AI Swarm (7 agents) → Self-Healing Git Patch
> ```

- [x] Add `aws-sdk-bedrockruntime` to dependencies in `src-tauri/Cargo.toml`
- [x] Create `nova_client.rs` implementation for Amazon Nova Bedrock wrapper
- [x] Implement `nova_shield.rs` containing `security_gate` and interceptors
- [x] Integrate `nova_shield` logic into `src-tauri/src/exec_engine.rs` / `trust_exec.rs` (terminal commands and file writes)
- [x] Create `attack_graph.rs` implementing `Graph-of-Graphs` logic from AST, Dependency, and Security Graphs
- [x] Implement `attack_path_search` (Dijkstra, max-flow/min-cut)
- [x] Implement `Self-Evolving` mechanism: save discovered exploit patterns into rules engine
- [x] Implement `Self-Evolving` mechanism: update `AstGraphNode -> PR chain` pipeline
- [x] Integrate with React Frontend for Live Attack Graph Visualization

## Phase 3: Reactive Graph Scheduler
- [x] Add `notify` crate to watch filesystem.
- [x] Create `scheduler.rs` Tokio background actor.
- [x] Integrate OS file-save events securely to the A2A Erlang-style `ActorRegistry`.

## Phase 4: Autonomous Git Patch Agent
- [x] Add `git2` crate to manage physical repository changes.
- [x] Create `git_agent.rs` to create safe branches (`nova-heal/...`).
- [x] Modify `PatchGenerator` to autonomously apply code fixes and stage+commit with the AI Root Cause.

## Phase 5: Unified "Graph-of-Graphs" UI Explorer (Pulse Graph)
- [x] Add telemetry `pulse-event` emission points in `scheduler.rs` and `ast_actor.rs`.
- [x] Build `PulseGraph.tsx` React Flow Canvas to visualize Erlang actors communicating in real-time.
- [x] Inject `PulseGraph` into the `AppLayout` Sidebar.

## Phase 6: LLM Verification Loop (Self-Correction)
- [x] Add compiler execution (`cargo check`) loop to `PatchGenerator`.
- [x] Implement Nova error-feedback loop for autonomous syntax auto-correction.
- [x] Add `Verifying` and `CodeBroken` visual states to the `PulseGraph` UI.

## Phase 7: Advanced SecQL (Deductive Reasoning Engine)
- [x] Add `crepe` Datalog macro crate for relation solving.
- [x] Define `Edge`, `Tainted`, `FlowsTo` transititive IDB rules.
- [x] Expose `run_full_datalog` as a Tauri query endpoint.

## Phase 8: Multi-Agent Swarm (Code Reviewer Agent)
- [x] Create `CodeReviewer` persona in `nova_client.rs`.
- [x] Inject `CodeReviewer` validation check into `PatchGenerator` before Git Commit.
- [x] Add `Reviewing` and `Rejected` UI visual states to the Pulse Graph.

## Phase 9: AI Swarm Enhancements
- [x] Create `ComplianceAgent` — audits patches against PCI DSS, EU CRA, NIST.
- [x] Add `ComplianceResult` and `RollbackPerformed` event types to `SwarmEvent`.
- [x] Implement live telemetry in `PitchDashboard.tsx` (real-time counters, activity feed).
- [x] Add Git Diff Viewer inline in `SwarmActivityModule.tsx`.
- [x] Implement Scenario Replay (`replay_demo` button).

## Phase 10: Next-Level Features
- [x] Create `AgentNeuralGraph.tsx` — animated SVG neural graph with pulsing agent nodes and message beams.
- [x] Multi-Vulnerability Cascade — `replay_demo` scripts 3 vulns (SQLi, XSS, CmdInjection).
- [x] AI Voice Narration — SpeechSynthesis API with ON/OFF toggle in PitchDashboard.
- [x] Real CVE Scanner — `scan_real_cves` command using `cargo audit --json`.

## Phase 11: Production-Ready Features
- [x] SBOM Export — `generate_sbom` command (CycloneDX 1.5 JSON, 8 components + vulns).
- [x] Interactive Agent Chat — `chat_with_nova` command (conversational AI via Bedrock).
- [x] Security Score Radar — SVG radar chart (6 metrics, overall score).
- [x] CI/CD Pipeline Generator — `generate_cicd_pipeline` (GitHub Actions YAML, 4 jobs).
- [x] Attack Surface Heatmap — 16 files with risk scores, "PATCHED" badge.
- [x] `SecurityToolsPanel.tsx` — 7 tabbed sub-panels.

## Phase 12: Polish & Presentation
- [x] `PitchSlides.tsx` — 6-slide pitch deck, fullscreen mode (F), keyboard navigation.
- [x] `generate_security_readme` — SECURITY.md with agent/CVE/compliance tables.
- [x] Desktop Notifications — Browser Notification API with ON/OFF toggle.

## Phase 13: WOW-Effect Features
- [x] Agent Performance Profiler — latency bars, sparklines, token counts per agent.
- [x] Multi-Language Vulnerability Demo — 6 languages (Rust, Python, JS, Go, C++, Java).
- [x] Threat Timeline — chronological event visualization with animated dots.
- [x] Achievements System — 8 gamification badges unlocked by swarm events.
- [x] Live Demo Script — automated presenter mode with progress bar.
- [x] `AdvancedFeaturesPanel.tsx` — 5 tabbed sub-panels.

## Phase 14: Enterprise Polish
- [x] `CommandPalette.tsx` — Ctrl+K overlay, 15+ commands, fuzzy search, keyboard nav.
- [x] `DependencyTreePanel.tsx` — interactive cargo dependency tree (25+ nodes, CVE markers).
- [x] `ExecutiveSummary.tsx` — one-page CTO report (metrics, risks, compliance, recommendation).

## Phase 15: Hyperscale Security Architecture
- [x] `TestPassed` SwarmEvent — Test Agent validates every patch (unit + integration + e2e).
- [x] `FuzzResult` SwarmEvent — Fuzz Agent: 2048 mutations, 0 crashes, 94.7% coverage.
- [x] `ExploitChainDetected` SwarmEvent — 4-stage exploit chain (SQLi → Cred Leak → Privesc → Shell).
- [x] `AttackPathEngine.tsx` — 5 tabs: Exploit Chains, Temporal Graph, Test Agent, Fuzz Agent, Event Store.
- [x] Enhanced `replay_demo` — full cascade: 3 CVE + Test + Fuzz + Exploit Chain Detection.
- [x] Temporal Graph — SVG before/after patch visualization with severed attack edges.
- [x] Event Store — persisted SwarmEvent log with timestamps and color-coded types.

## Phase 16: Graph-Scheduled Distributed Agent Swarm
- [x] `TestFailed` SwarmEvent — triggers PatchAgent retry cycle.
- [x] `DependencyRisk` SwarmEvent — triggers ThreatIntel taint scan.
- [x] `PolicyViolation` SwarmEvent — pre-emptive compliance check before patching.
- [x] `trigger_swarm_demo` — non-linear 5-phase graph-scheduled demo (not pipeline).
- [x] Crash fix — deterministic demo flow, safe string slicing.
- [x] Hyperscale architecture diagram (Section 7, pitch_architecture.md).
- [x] Graph-of-Graphs mapping + 12-event SwarmEvent table in ARCHITECTURE.md.

## Phase 17: Exploit Simulation Engine (Red Team vs Blue Team)
- [x] `ExploitSimulation` SwarmEvent (13th variant) — phase, attacker, defender, severity, node_path.
- [x] `run_exploit_simulation` Tauri command — 5 phases: Recon → Exploit → Lateral → Escalation → Exfiltration.
- [x] 🎯 Exploit Sim tab in AttackPathEngine.tsx — severity bars, phase icons, node path, Launch button.
- [x] Self-play: Red Team attacker vs Blue Team defender — 2/5 phases blocked, MTTR 4.8s.
- [x] Documentation synced: ARCHITECTURE.md (13 events), pitch_architecture.md, hackathon_demo_guide_ru.md.
