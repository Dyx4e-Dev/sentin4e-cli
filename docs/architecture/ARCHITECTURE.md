# Sentin4e: Target State Architecture

This document defines the target-state software architecture for Sentin4e. It is designed to support the evolution from a synchronous, single-target CLI to a high-concurrency security platform capable of automated remediation, advanced WAF evasion, and active defense proxying.

---

## 1. High-Level Architecture Overview

Sentin4e is structured as a pipeline of independent subsystems:

1.  **Configuration & State:** Ingestion of CLI flags, environment variables, config files, and target lists.
2.  **Orchestration Layer:** Concurrency management, task queuing, and rate limiting.
3.  **Network Engine:** Asynchronous HTTP client with low-level TLS/socket manipulation capabilities.
4.  **Analysis Engines:** Stateless security logic for header validation, WAF detection, and fuzzing.
5.  **Post-Processing Analytics:** Heuristic clustering, shadow API correlation, and root-cause analysis.
6.  **Remediation & Export:** IaC patch generation, SARIF formatting, Webhooks, and Terminal UI rendering.

By strictly decoupling networking from analysis, Sentin4e can seamlessly route data from standard HTTP scans, raw TLS sockets, or an active reverse proxy through the exact same validation logic.

---

## 2. Core Modules and Responsibilities

The architecture is broken down into distinct, heavily decoupled modules:

### `sentin4e.net` (Networking & Evasion)
Handles all outbound traffic. Built on `asyncio` and `httpx`, it manages redirects, retries, and rate limiting. It also contains the `tls_spoofer` for JA3/JA4 manipulation and the `raw_inspect` fallback for malformed responses.

### `sentin4e.scanner` (Orchestration)
The central nervous system. It takes a list of targets (from CLI or file), chunks them, and feeds them into the `net` layer concurrently. It then routes the HTTP responses to the registered `engines`.

### `sentin4e.engines` (Stateless Analysis)
The core detection logic. Engines take an HTTP response and return a list of `Finding` objects.
*   **Header Engine:** Validates security headers (HSTS, CSP, etc.).
*   **WAF Engine:** Detects security appliances via headers/cookies.
*   **Fuzzer Engine (v4):** Detects state-machine desyncs.

### `sentin4e.analytics` (Intelligence)
Analyzes bulk findings. It performs clustering based on TLS certificates or Server headers (Root-Cause Clustering) and identifies anomalies (Shadow API Correlator).

### `sentin4e.models` (Data Contracts)
Pydantic schemas that define the internal API. Everything passing between modules must adhere to these schemas (`Target`, `ResponseContext`, `Finding`, `ReportV2`).

### `sentin4e.exporters` (Output Layer)
Consumes the final `Report` objects and formats them to the requested output (JSON, SARIF, Rich Terminal, Webhooks).

---

## 3. Internal Package Structure

```text
sentin4e/
├── cli/                 # User interfaces
│   ├── commands.py      # Typer CLI entrypoints
│   ├── shell.py         # Prompt-Toolkit interactive shell
│   └── tui.py           # Textual-based terminal dashboard
├── config/              # Configuration management (YAML/TOML loader)
├── models/              # Pydantic schemas and data contracts
├── net/                 # Asynchronous network layer
│   ├── client.py        # httpx wrapper
│   ├── raw_socket.py    # Fallback inspection
│   └── tls_spoof.py     # JA3/JA4 shifting (v2)
├── scanner/             # Orchestration and concurrency
│   └── orchestrator.py
├── engines/             # Pluggable detection logic
│   ├── headers.py       # Core security header rules
│   ├── waf.py           # WAF signatures
│   ├── fuzzer.py        # Active state-machine fuzzing (v4)
│   └── origin.py        # Origin unveiling (v2)
├── analytics/           # Post-scan analysis
│   ├── clustering.py    # Root-cause analysis (v3)
│   └── shadow_api.py    # Heuristic fingerprinting (v2)
├── remediation/         # Automated fix generation
│   ├── iac_patch.py     # Terraform/Nginx snippet generation (v3)
├── proxy/               # Active defense (v4)
│   └── healing_proxy.py # ASGI reverse proxy
├── exporters/           # Output formatting
│   ├── sarif.py         # CI/CD integration
│   ├── webhook.py       # Event callbacks
│   └── formatter.py     # Rich terminal output
└── plugins/             # External user-defined rules and hooks
```

---

## 4. Scan Lifecycle & Data Flow

1.  **Ingestion:** The user runs `sentin4e scan -i targets.txt`. The `cli` module parses the args and merges them with `.sentin4e.yaml` via the `config` module.
2.  **Dispatch:** The `orchestrator` takes the targets and builds a queue of async tasks.
3.  **Execution:** The `net` module fetches targets concurrently. If a WAF block is detected, it rotates TLS fingerprints. If standard parsing fails (e.g., >100 headers), it falls back to `raw_socket`.
4.  **Analysis:** The raw HTTP responses are converted into a standard `ResponseContext` model and piped to the `engines` layer.
5.  **Aggregation:** All `Finding` objects are passed to the `analytics` layer. The clustering engine groups identical findings (e.g., 50 subdomains missing HSTS behind the same load balancer).
6.  **Scoring & Remediation:** The scoring engine calculates the final grades, and the `remediation` module attaches IaC snippets to the findings.
7.  **Export:** The final structured data is passed to `exporters` where it is concurrently printed to the terminal, saved to SARIF, and POSTed to a webhook.

---

## 5. Plugin Extension Points

To maintain a closed core but allow enterprise customization, Sentin4e implements a lightweight hook architecture (via `pluggy` or a simple observer pattern).

*   `on_request_created(request)`: Modify headers/auth before sending.
*   `on_response_received(response)`: Allows custom engines to analyze the response.
*   `on_report_generated(report)`: Allows custom exporters (e.g., Jira ticket creation).

---

## 6. Shared Interfaces & Design Principles

*   **Stateless Analysis:** Analysis engines must never make network calls. They strictly consume a `ResponseContext` and return `Finding` objects. This makes them 100% unit-testable and allows them to be reused by the v4 Healing Proxy.
*   **Fail-Safe Networking:** The network layer must expect failure (Timeouts, WAF TCP Resets, Malformed HTTP). Exceptions must be caught at the `net` boundary and converted into a `Target(scan_integrity="FAILED")` object, ensuring the orchestrator never crashes.
*   **Data Immutability:** Once a `ResponseContext` is generated, it cannot be mutated. Engines read it and append findings to an isolated list.
*   **Configuration as Dependency Injection:** Settings (timeouts, user agents, proxy endpoints) are not global variables. They are loaded into a `ConfigContext` object that is passed down the stack.

---

## 7. Future Scalability Considerations

*   **Async Native:** By moving from `requests` to `httpx`/`asyncio` in v1, the architecture will support scanning 10,000+ assets efficiently without thread-pool starvation.
*   **The Healing Proxy (v4):** Because analysis engines are stateless, the `proxy` module can simply intercept ASGI traffic, pass the response headers to the `engines.headers` module, read the missing recommendations, dynamically append those headers to the ASGI response, and forward it to the client. The core logic remains identical.
*   **Decoupled Exporting:** Because exporting happens entirely post-scan using strict Pydantic schemas, adding a new exporter (e.g., `ElasticsearchExporter`) requires zero changes to the analysis or networking layers.
