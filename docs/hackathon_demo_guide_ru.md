# Autonomous Graph-Driven DevSecOps Engine: Руководство по демо для хакатона

## 1. Обзор и архитектура
В этом документе описывается **Autonomous Graph-Driven DevSecOps Engine** — система, объединяющая 5 вычислительных парадигм в одном Rust-бинарнике:

```
Codebase → AST Graph → Attack Graph (Datalog) → Actor Runtime → AI Swarm (8 agents) → Exploit Simulation → Self-Healing Git Patch
```

| Парадигма | Реализация |
|-----------|------------|
| Erlang/OTP Actors | SwarmBus broadcast + ActorRegistry |
| Datalog Reasoning | Crepe DB — FlowsTo, Tainted, Edge |
| Multi-Agent AI | 7 агентов: Threat → Patch → Review → Compliance → Test → Fuzz → AttackPathAI |
| Reactive Graph | notify file watcher → AST cascade → auto-scan |
| Self-Healing Pipeline | Nova generate → cargo check → Git auto-commit |

Бэкенд на базе **Amazon Nova 2 Lite** анализирует в реальном времени графы AST, зависимостей и безопасности, выстраивает пути атаки и автономно генерирует патчи.

### 1.1 Граф Графов (The Graph-of-Graphs)
- **AST Граф**: Формируется парсерами (Функции, Импорты, Эндпоинты, Вызовы).
- **Граф Зависимостей**: Формируется через SBOM (Библиотеки, Уязвимости).
- **Граф Безопасности**: Потоки данных через границы доверия (Аутентификация, Файловая система, Shell, Сеть).
- **Механизм Графа Атак (Attack Graph Engine)**: Объединяет эти три источника. Использует стандартные алгоритмы на графах, такие как Дейкстра, для нахождения Кратчайшего Пути Эксплуатации (например, `HTTP Input -> Parse -> Concat -> Shell Exec`).

## 2. Реактивное Ядро (AST Node Actor)
Вместо статического парсинга мы используем `AstNodeActor` (GenServer в стиле Erlang/OTP).

- **Событийно-ориентированность (Event-Driven)**: Если разработчик допускает опечатку или изменяет файл, срабатывает событие `SourceChanged`.
- **Каскадная инвалидация (Cascading Invalidation)**: Граф AST распространяет изменение состояния. Любой узел, зависящий от измененного узла (`DependencyChanged`), сбрасывается в состояние `Unparsed` (Не разобран).
- **Шлюз Nova Shield Gate**: Если намерение выполнения (execution intent) опасно (например, `system()`), Nova помечает это намерение. Узел AST переходит в состояние `Quarantined` (На карантине).

## 3. Механизм Самоэволюции и Исцеления
Это наша "Убойная фича" (Killer Feature) для демо на хакатоне. Она демонстрирует *Автоматизированную защиту с машинным обучением*.

Когда `AstNodeActor` попадает в `Quarantined`:
1. **Генератор Патчей Nova (Nova Patch Generator)**: Узел отправляет свой код в Amazon Nova 2.
2. Nova отвечает двумя критически важными артефактами:
   - **Патч кода (Code Patch)**: Безопасный рефакторинг (например, замена `system()` на `Command::new()`).
   - **Извлечение статического правила (Static Rule Extraction)**: Оптимизированный шаблон SECQL или регулярное выражение, которое перехватывает *именно этот* семантический вектор атаки.
3. **Эволюция Механизма (Engine Evolution)**: Сгенерированное правило немедленно внедряется в локальный Движок Правил (`src-tauri/src/rules.rs`), обучая DevSecOps агента отлавливать эту уязвимость *локально, за миллисекунды*, в будущем без необходимости вызова LLM.

## 4. Фаза 6: Цикл Верификации LLM (Самокоррекция)
Сгенерированный код больше не коммитится вслепую.
1. `PatchGenerator` записывает код и запускает **Компилятор Rust (`cargo check`)**.
2. Если компиляция падает (например, ошибка Borrow Checker), `stderr` парсится и скармливается **обратно** в Nova.
3. ИИ и Компилятор спорят в цикле, пока код не станет синтаксически идеальным.

## 5. Фаза 8: Рой Мульти-Агентов (Консенсусное Ревью)
Прежде чем синтаксически идеальный код попадет в Git, он сталкивается с **Роем (Swarm)**:
1. Патч отправляется **второму логическому инстансу LLM**, который действует строго как Элитный Аудитор Безопасности (Elite Security Auditor).
2. Ревьюер активно ищет вторичные уязвимости, регрессии или логические бомбы.
3. Если статус `REJECTED` (ОТКЛОНЕНО), критика отправляется обратно Генератору.
4. Только после консенсуса `APPROVED` (ОДОБРЕНО), `GitAgent` автоматически создает безопасную ветку и коммитит исправление!

## 6. Фаза 7: Advanced SecQL (Механизм Дедуктивного Вывода)
Мы заменили стандартный обход графа на Datalog Механизм реального времени (`crepe`).
- Транзитивные отношения (`FlowsTo(x, z) <- Edge(x, y), FlowsTo(y, z)`) мгновенно находят глубокие, многошаговые косвенные пути атак.
- **Радиус Поражения и Распад Доверия (Blast Radius & Trust Decay)**: Datalog движок математически доказывает, как недоверенные компоненты (с отсутствующими хешами SBOM) заражают всё нисходящее дерево зависимостей.

## 7. Фронтенд Визуализация (Живой Пульс-Граф)
React-фронтенд (`PulseGraph.tsx`) наглядно отслеживает жизненный цикл процесса самоисцеления в реальном времени.

- **[Синий] Parsed** ➔ **[Красный] Vulnerable** ➔ **[Фиолетовый] Verifying** (ИИ против Компилятора)
- **[Лазурный] Reviewing** (ИИ против ИИ) ➔ **[Розовый] Rejected** (Спор)
- **[Зеленый] Healed** (Консенсус достигнут и код закомичен в Git)

---

## 8. Фазы 9–14: Продуктовый блеск

### 8.1 Фаза 9: Расширение Swarm
- **Compliance Agent** — автономный аудит патчей по PCI DSS 6.5.1, EU CRA Art.10, NIST SP 800-218 (SSDF)
- **Инлайн Git Diff Viewer** — визуализация изменений прямо в карточках SwarmActivity
- **Scenario Replay** — кнопка «REPLAY DEMO» запускает 3-уязвимостный каскад (SQLi → XSS → CmdInjection)

### 8.2 Фаза 10: Neural Graph + Voice
- **AgentNeuralGraph** (`AgentNeuralGraph.tsx`) — анимированная SVG-визуализация: 5 агентов как пульсирующие узлы, сообщения летят лучами между ними в реальном времени
- **AI Voice Narration** — SpeechSynthesis API озвучивает события Swarm
- **Real CVE Scanner** — `cargo audit --json` сканирует реальные CVE зависимостей

### 8.3 Фаза 11: Security Tools Dashboard (7 табов)
| Таб | Описание |
|-----|----------|
| 📈 Security Score | SVG-радар (6 метрик, общий балл) |
| 💬 Nova Chat | Диалог с ИИ через Bedrock |
| 📦 SBOM Export | CycloneDX 1.5 JSON + скачивание |
| 🔗 CI/CD Generator | GitHub Actions YAML (4 джоба) |
| 🗺️ Attack Heatmap | 16 файлов с risk-score |
| 📜 SECURITY.md | Auto-генерация SECURITY.md |
| 🔔 Desktop Alerts | Нативные уведомления ОС |

### 8.4 Фаза 12: Pitch Mode
- **PitchSlides** — 6 слайдов: Problem → Solution → Architecture → Demo → Impact → Built With
- Полноэкранный режим (клавиша **F**), навигация стрелками
- Идеально для проекции на экран хакатона

### 8.5 Фаза 13: WOW-Effect Features (5 табов в Advanced)
| Таб | Описание |
|-----|----------|
| ⏱️ Agent Profiler | Latency bars + sparklines + token count |
| 🌐 Multi-Language | 6 языков: Rust, Python, JS, Go, **C++**, **Java** |
| 📊 Threat Timeline | Хронологическая шкала с цветными точками |
| 🏆 Achievements | 8 бейджей: First Blood, Speed Demon, Triple Kill... |
| 🎯 Demo Script | Автоматический презентер — всё по одной кнопке |

### 8.6 Фаза 14: Enterprise Polish
- **⌨️ Command Palette** (`Ctrl+K`) — 15+ команд, fuzzy-поиск, навигация клавиатурой
- **🌳 Dependency Tree** — интерактивное дерево 25+ Cargo зависимостей с CVE-маркерами
- **📱 Executive Report** — одностраничный отчёт для CTO с метриками, рисками, compliance

### 8.7 Фаза 15: Hyperscale Architecture
- **🧪 Test Agent** — автоматическое тестирование каждого патча (unit + integration + e2e)
- **🔀 Fuzz Agent** — мутационное тестирование (2048 мутаций, coverage до 94.7%)
- **⛓️ Multi-Stage Exploit Chain** — 4-стадийная цепочка: SQLi → Credential Leak → Privilege Escalation → Root Shell
- **🕐 Temporal Graph** — SVG-визуализация Before/After: красные узлы → зелёные, attack edges перечёркнуты
- **📡 Event Store** — персистентное хранилище SwarmEvent с таймстампами
- **Компонент `AttackPathEngine.tsx`** — 5 табов: Exploit Chains, Temporal Graph, Test Agent, Fuzz Agent, Event Store

---

## 9. Конкурентный анализ

| Конкурент | Datalog | Self-Healing | Actor Runtime | Graph-Native | AI Swarm |
|-----------|---------|-------------|---------------|-------------|----------|
| **Nova Shield** | ✅ Crepe | ✅ Auto-patch | ✅ Erlang/OTP | ✅ MetaGraph | ✅ 7 agents |
| GitHub CodeQL | ✅ | ❌ | ❌ | ❌ | ❌ |
| Snyk | ❌ | ❌ | ❌ | ❌ | ❌ |
| Palo Alto Prisma | ❌ | ❌ | ❌ | ❌ | ❌ |
| Semgrep | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## 10. Порядок демо на хакатоне

1. **Откройте Pitch Slides** (🎬) → покажите Problem/Solution/Architecture (**30 сек**)
2. Нажмите **F** для fullscreen
3. Перейдите на **Dashboard** (🚀) → нажмите **LAUNCH SELF-HEALING** (**60 сек**)
4. Покажите **Neural Graph** — агенты пульсируют, лучи летают
5. Нажмите **REPLAY DEMO** — покажите полный каскад: 3 CVE → Test → Fuzz → Exploit Chain
6. Переключитесь на **🔎 Attack-Path AI → ⛓️ Exploit Chains** — 4-стадийная цепочка с маркерами PATCHED
7. Покажите **🕐 Temporal Graph** — Before (красный) → After (зелёный)
8. Откройте **🧪 Test Agent** — 25/25 tests passed
9. Откройте **🔀 Fuzz Agent** — 2048 мутаций, 0 крашей, 94.7% coverage
10. Перейдите на **🎯 Exploit Sim** → нажмите **🚀 Launch Simulation** — Red Team vs Blue Team в реальном времени
11. Покажите **🌳 Dependency Tree** — раскройте ветви с CVE
12. Откройте **📱 Executive Report** — метрики для CTO
13. Нажмите **Ctrl+K** → наберите "sbom" → скачайте SBOM (**WOW!**)
14. Финал: слайд **Impact** (197 дней → 30 секунд)

> **Общее время демо: 4–6 минут**

---
*Autonomous Graph-Driven DevSecOps Engine. 8 агентов · 13 SwarmEvent · Exploit Simulation Engine. Работает на базе Amazon Bedrock, Rust (Tokio, Petgraph, Crepe) и React / Tauri v2.*
