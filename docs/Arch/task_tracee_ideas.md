# Идеи из Tracee → CycloneDX Tauri UI

> **Дата**: 2026-03-05  
> **Источник**: Tracee v33.33.34 (Aqua Security)  
> **Цель**: CycloneDX Tauri UI v0.2.0+

---

## Сравнение архитектур

```mermaid
graph LR
    subgraph "Tracee"
        T1["6-stage Pipeline<br/>decode→match→process<br/>→derive→detect→sink"]
        T2["Detector Registry<br/>35 Go + 21 YAML"]
        T3["Policy Manager<br/>dynamic filters + snapshots"]
        T4["DataStores<br/>7 runtime stores"]
        T5["gRPC Streaming<br/>real-time events"]
        T6["Derivation Table<br/>event → derived events"]
        T7["traceectl CLI<br/>separate binary"]
    end

    subgraph "CycloneDX Tauri UI"
        C1["DAG Engine<br/>topological execution"]
        C2["7 узлов DAG<br/>validate, merge, scan..."]
        C3["Settings<br/>air-gap, proxy, SSL"]
        C4["ArtifactStore<br/>2 реализации"]
        C5["Tauri emit()<br/>event streaming"]
        C6["—"]
        C7["—"]
    end

    T1 -.->|"идея"| C1
    T2 -.->|"идея"| C2
    T3 -.->|"идея"| C3
    T4 -.->|"идея"| C4
    T5 -.->|"идея"| C5
```

---

## Фазы развития CycloneDX Tauri UI (из Tracee)

### Фаза 5 — Детекторы и правила (Registry Pattern)

Tracee: 35 Go-сигнатур + 21 YAML-правил через `Detector Registry` + `Dispatch`.  
**Идея**: Создать аналогичный `RuleRegistry` для CycloneDX — декларативные YAML-правила проверки SBOM.

| # | Задача | Источник в Tracee | Приоритет | Сложность |
|---|--------|------------------|-----------|-----------|
| 5.1 | **RuleRegistry** — реестр проверочных правил (Rust trait + HashMap) | `pkg/detectors/registry.go` (23KB) | 🔴 Высокий | Средняя |
| 5.2 | **YAML Rule Engine** — загрузка правил из YAML без перекомпиляции | `pkg/detectors/yaml/` (21 файл) | 🔴 Высокий | Средняя |
| 5.3 | **Rule Dispatch** — маршрутизация SBOM → правила по типу/scope | `pkg/detectors/dispatch.go` (12KB) | 🟡 Средний | Низкая |
| 5.4 | **Custom NIST Rules** — YAML-правила для конкретных требований NIST | — | 🟡 Средний | Низкая |

**Пример YAML-правила:**
```yaml
id: FSTEC-LICENSE-CHECK
name: "Проверка лицензий компонентов"
description: "Все компоненты SBOM должны иметь лицензию"
severity: error
scope:
  artifact_types: [SBOM, ValidatedSBOM]
condition:
  field: "components[*].licenses"
  operator: "not_empty"
  threshold: 80  # минимум 80% с лицензиями
```

---

### Фаза 6 — DataStore Registry (Enrichment Pattern)

Tracee: 7 DataStores (container, DNS, process, symbol, syscall, system, IP rep) через единый `Registry`.  
**Идея**: Создать `DataSourceRegistry` для обогащения SBOM внешними данными.

| # | Задача | Источник в Tracee | Приоритет | Сложность |
|---|--------|------------------|-----------|-----------|
| 6.1 | **DataSourceRegistry** — единый реестр источников данных | `pkg/datastores/registry.go` (10KB) | 🟡 Средний | Средняя |
| 6.2 | **VulnDB Store** — кэш уязвимостей (OSV, NVD) для offline-enrichment | `pkg/datastores/ipreputation/` | 🔴 Высокий | Высокая |
| 6.3 | **LicenseDB Store** — SPDX license database для валидации | `pkg/datastores/dns/` (кэш паттерн) | 🟡 Средний | Средняя |
| 6.4 | **SupplierDB Store** — база поставщиков для NIST-проверок | — | 🟢 Низкий | Низкая |

---

### Фаза 7 — Pipeline-стадии (Multi-Stage Pattern)

Tracee: 6 стадий pipeline с goroutine-каналами (decode→match→process→derive→detect→sink).  
**Идея**: Расширить DAG Engine стадиями pre/post-processing.

| # | Задача | Источник в Tracee | Приоритет | Сложность |
|---|--------|------------------|-----------|-----------|
| 7.1 | **Enrichment Stage** — автоматическое обогащение SBOM данными из DataStores | `processEvents` (enrichment) | 🔴 Высокий | Средняя |
| 7.2 | **Derivation Stage** — вывод производных артефактов (SBOM → VEX, SBOM → License Report) | `deriveEvents` (derivation table) | 🟡 Средний | Средняя |
| 7.3 | **Sink Stage** — множественные выходы: файл + gRPC + webhook одновременно | `sinkEvents` (multi-printer) | 🟡 Средний | Низкая |
| 7.4 | **Pipeline Metrics** — Prometheus-метрики для каждой стадии | `pkg/metrics/` | 🟢 Низкий | Низкая |

---

### Фаза 8 — Policy System (Dynamic Filtering)

Tracee: `PolicyManager` с dynamic filters, atomic snapshots, eBPF filter maps.  
**Идея**: Динамические политики для SBOM-валидации — профили проверок по окружению.

| # | Задача | Источник в Tracee | Приоритет | Сложность |
|---|--------|------------------|-----------|-----------|
| 8.1 | **ValidationProfile** — профили валидации (dev/staging/prod/NIST) | `pkg/policy/policy.go` (3KB) | 🔴 Высокий | Средняя |
| 8.2 | **Profile CRUD** — UI для создания/редактирования профилей | `pkg/policy/policy_manager.go` (17KB) | 🟡 Средний | Средняя |
| 8.3 | **Profile Templates** — предустановленные шаблоны (NIST, NTIA-min, CRA) | — | 🟡 Средний | Низкая |
| 8.4 | **Policy Snapshots** — версионирование профилей для аудита | `pkg/policy/snapshots.go` (4KB) | 🟢 Низкий | Низкая |

---

### Фаза 9 — gRPC API & CLI (Remote Control)

Tracee: gRPC-сервер + `traceectl` CLI + Proto definitions.  
**Идея**: Headless-режим CycloneDX Tauri UI с gRPC API для CI/CD автоматизации.

| # | Задача | Источник в Tracee | Приоритет | Сложность |
|---|--------|------------------|-----------|-----------|
| 9.1 | **REST API** — HTTP API для запуска пайплайнов без UI | `pkg/server/http/` | 🔴 Высокий | Средняя |
| 9.2 | **CLI mode** — `cyclonedx-ui --headless --pipeline pipeline.json` | `cmd/traceectl/` | 🟡 Средний | Средняя |
| 9.3 | **Event Streaming** — SSE/WebSocket для real-time pipeline progress | `gRPC streaming` | 🟡 Средний | Средняя |
| 9.4 | **CI Integration** — GitHub Actions / GitLab CI template | — | 🟡 Средний | Низкая |

---

## Матрица приоритетов

```mermaid
quadrantChart
    title Приоритет vs Сложность
    x-axis Низкая сложность --> Высокая сложность
    y-axis Низкий приоритет --> Высокий приоритет
    quadrant-1 Делать первым
    quadrant-2 Планировать
    quadrant-3 Можно отложить
    quadrant-4 Делать вторым

    "5.1 RuleRegistry": [0.45, 0.85]
    "5.2 YAML Rules": [0.50, 0.85]
    "6.2 VulnDB": [0.75, 0.90]
    "7.1 Enrichment": [0.50, 0.80]
    "8.1 ValidationProfile": [0.45, 0.85]
    "9.1 REST API": [0.55, 0.80]
    "5.3 Dispatch": [0.30, 0.55]
    "6.3 LicenseDB": [0.50, 0.55]
    "7.2 Derivation": [0.50, 0.55]
    "8.2 Profile CRUD": [0.55, 0.55]
    "7.3 Multi-Sink": [0.25, 0.55]
    "9.2 CLI mode": [0.50, 0.55]
    "7.4 Metrics": [0.25, 0.35]
    "8.4 Snapshots": [0.30, 0.35]
```

---

## Рекомендованный порядок реализации

| Приоритет | Фаза | Ключевая ценность | Усилие |
|-----------|------|-------------------|--------|
| **1** | Фаза 5 — Детекторы | YAML-правила без перекомпиляции → гибкость | 2-3 дня |
| **2** | Фаза 8 — Политики | Профили dev/prod/NIST → Compliance-as-Code | 1-2 дня |
| **3** | Фаза 6 — DataStores | VulnDB + LicenseDB → offline enrichment | 2-3 дня |
| **4** | Фаза 7 — Pipeline | Enrichment + derivation → автоматизация | 2-3 дня |
| **5** | Фаза 9 — API & CLI | Headless + CI/CD → enterprise adoption | 3-4 дня |
