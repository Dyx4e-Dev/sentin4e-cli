# Sentin4e Technical Specification

## 1. Project Overview

### 1.1 Vision
Sentin4e aims to be the premier open-source offensive security platform and defensive diagnostic tool, empowering security professionals, red teams, and DevSecOps engineers with robust, reliable, and secure CLI-based tooling. It bridges the gap between fast, ad-hoc terminal hacking tools and mature, enterprise-grade static/dynamic analysis platforms.

### 1.2 Scope
The Sentin4e platform encompasses CLI tool development, static and dynamic analysis modules, threat modeling utilities, and rich cross-platform terminal user interfaces. It is designed to act as a foundational framework upon which security researchers can build custom detection and exploitation workflows.

### 1.3 Non-goals
*   **GUI Applications:** No desktop or web-based graphical user interfaces will be developed in the core repository. The project is strictly terminal-first.
*   **Kernel-level Drivers:** The project operates in user-space.
*   **Unsupervised Exploitation:** Sentin4e is not a replacement for Metasploit. It is a diagnostic and analysis tool, not an automated "point-and-shoot" exploitation framework.

### 1.4 Design Philosophy
*   **Clean Architecture:** Strict boundaries between CLI presentation, business logic, and I/O.
*   **Secure by Default:** Zero-trust input handling; always assume data (even local files) is malicious or malformed.
*   **Exceptional UX:** Provide beautiful, readable, and interactive CLI experiences using modern libraries (Rich, Typer).
*   **Uncompromising Reliability:** Fail securely, recover gracefully, and never leak internal stack traces or secrets to standard output.

---

## 2. Technical Requirements

### 2.1 Supported Python Versions
*   Python 3.10 and above. Features from older Python versions must not restrict the use of modern syntax (e.g., structural pattern matching, modern typing).

### 2.2 Supported Operating Systems
*   **Linux:** Ubuntu/Debian, RHEL/CentOS, Arch Linux.
*   **Windows:** Windows 10/11, Windows Server 2019+.
*   **macOS:** macOS 13 (Ventura) and newer.

### 2.3 Minimum Dependency Policy
To minimize supply chain risks, third-party dependencies are strictly limited. 
*   Core dependencies are restricted to established, well-maintained libraries (e.g., `typer`, `rich`, `pydantic`).
*   Any proposed new dependency requires a documented justification and a mandatory security review of the package's maintainer history and source code.

### 2.4 Cross-Platform Compatibility Requirements
*   **File Systems:** Always use `pathlib.Path` for path manipulations. Never use hardcoded slashes or `os.path` string concatenations.
*   **Subprocesses:** Must handle OS-specific path and quoting differences gracefully (e.g., `shlex.quote` equivalents on Windows).
*   **Encoding:** Default to UTF-8 for all file reads/writes unless a specific encoding is dynamically detected.

---

## 3. Architecture Principles

### 3.1 Separation of Concerns
Strict decoupling is enforced between the CLI presentation layer (input parsing, formatting), business logic (security analysis engines), and data access layers (file reading, network requests). 

### 3.2 Stateless Analysis Engines
Analysis engines must be purely functional where possible, maintaining no mutable global state across execution contexts. Given identical inputs, engines must produce identical outputs.

### 3.3 Immutable Data Models
Internal data representations must use Python `@dataclass(frozen=True)` or Pydantic immutable models. State mutations are handled by returning new instances rather than modifying existing ones.

### 3.4 Modular Architecture
Sentin4e relies on a plugin-based architecture. New security analysis modules, parsers, and formatters must be implementable without modifying core engine code.

### 3.5 Dependency Inversion
High-level modules (e.g., the CLI runner) must not depend on low-level modules (e.g., a specific static analysis tool). Both must depend on abstractions (Python `Protocols` or Abstract Base Classes).

### 3.6 Fail-Safe Design
*   Assume all user input, network responses, and file contents are malicious.
*   In the event of a critical failure, the application must fail securely, preventing information leakage (no raw stack traces to users unless `--debug` is passed).
*   Non-fatal errors (e.g., failing to parse one file in a directory of thousands) must be logged and bypassed, allowing the scan to continue.

### 3.7 Extensibility
The architecture must natively support external hooks, allowing integration into DevSecOps pipelines, CI/CD runners, and incident response automation platforms.

---

## 4. Coding Standards

### 4.1 Naming Conventions
*   PEP 8 compliant.
*   `snake_case` for variables, functions, and modules.
*   `PascalCase` for classes and types.
*   `UPPER_SNAKE_CASE` for global constants.

### 4.2 Package Organization
Code must be grouped by feature domain, not by technical type:
*   `sentin4e.cli` - Command-line interface definitions (Typer).
*   `sentin4e.core` - Core business logic, interfaces, and configurations.
*   `sentin4e.plugins` - Implementations of specific security checks.
*   `sentin4e.utils` - Pure helper functions (networking, crypto, filesystem).

### 4.3 Type Hints
Strict static typing is required on **100%** of function and method signatures. Code must pass `mypy --strict` without suppressing global errors.

### 4.4 Documentation Requirements
*   Google-style docstrings are required for all public modules, classes, and functions.
*   Major architectural changes or new modules require an Architecture Decision Record (ADR).

### 4.5 Logging Standards
*   Use the standard `logging` module configured with `rich.logging.RichHandler` for terminal output.
*   **NEVER** use `print()` for operational logic or data output.
*   Avoid logging sensitive information (PII, credentials, API keys).

### 4.6 Error Handling Rules
*   Catch specific exceptions (`except FileNotFoundError:`, not `except Exception:`).
*   No bare `except:` blocks under any circumstances.
*   Use custom exception classes inheriting from a base `Sentin4eError` to distinguish application logic errors from standard library errors.

### 4.7 Configuration Management
Configuration is resolved via a prioritized chain:
1.  CLI Arguments (Highest Priority)
2.  Environment Variables
3.  Configuration Files (TOML)
4.  Secure Defaults (Lowest Priority)

### 4.8 Testing Expectations
*   Minimum **85%** code coverage required for all pull requests.
*   Unit tests for all business logic and edge cases.
*   Integration tests for end-to-end CLI workflows.
*   Regression tests for previously identified vulnerabilities or critical bugs.

---

## 5. Performance Requirements

### 5.1 Startup Performance Goals
CLI applications must display help menus or begin execution within **200 milliseconds**. Heavy imports (e.g., large ML models, complex parsing libraries) must be deferred until the specific command requiring them is invoked.

### 5.2 Memory Usage Expectations
The application must maintain a bounded memory footprint. Use stream processing and generators for large files. Never load multi-gigabyte files or complete directory structures entirely into RAM.

### 5.3 Network Timeout Policies
All network operations must have explicit, configurable timeouts to prevent hanging. Default timeouts: 10 seconds for connection, 30 seconds for read operations.

### 5.4 Concurrency Guidelines
*   Use `asyncio` for I/O-bound tasks (network scanning, API requests).
*   Use `multiprocessing` for CPU-bound tasks (cryptography, deep static analysis).
*   Avoid standard `threading` for CPU work due to Python's Global Interpreter Lock (GIL).

### 5.5 Large-Scale Scanning Targets
The architecture must efficiently support processing 10,000+ files or network endpoints simultaneously without UI freezing, deadlock, or resource exhaustion.

---

## 6. Versioning Strategy

### 6.1 Semantic Versioning
Strict adherence to Semantic Versioning (MAJOR.MINOR.PATCH).
*   MAJOR: Incompatible API or CLI flag changes.
*   MINOR: Backwards-compatible new functionality.
*   PATCH: Backwards-compatible bug fixes.

### 6.2 Feature Freeze Policy
A mandatory one-week feature freeze precedes major and minor releases to allow for stabilization, extensive integration testing, and security auditing.

### 6.3 Deprecation Policy
Deprecated features, APIs, or CLI flags must emit runtime warnings (via the `logging` module) for at least one minor release before being completely removed in the next major release.

### 6.4 Backward Compatibility
CLI flags, configuration file schemas, and public plugin API interfaces must remain stable across all minor and patch versions within a major release cycle.

---

## 7. Release Process

### 7.1 Development Workflow
*   Trunk-based development (`main` is always stable).
*   All changes must be submitted via Feature Branches and Pull Requests (PRs).

### 7.2 Code Review Requirements
*   Two independent approvals from core maintainers required for merge.
*   Mandatory passing of all automated CI checks (linters, type checkers, SAST scanners, unit tests).

### 7.3 Testing Requirements
CI/CD pipelines must execute the full test suite on Windows, Linux, and macOS across all supported Python versions (3.10+).

### 7.4 Release Checklist
Before tagging a release, the following must be completed:
1.  Automated security scan (SAST/DAST) of the codebase.
2.  Dependency vulnerability audit (`pip-audit` or similar).
3.  Automated changelog generation.
4.  Documentation build and validation.
5.  PyPI publish step using Trusted OIDC Publishers (no hardcoded credentials).

---

## 8. Documentation Standards

No feature or module will be merged without meeting the following minimum documentation requirements:
1.  **Code-level:** Docstrings on all newly introduced classes, methods, and functions.
2.  **User-facing:** Updates to the official CLI usage documentation (`docs/usage.md`).
3.  **Examples:** A working example, script, or configuration snippet added to the `/examples` directory demonstrating the new feature.
4.  **Architecture:** If the feature introduces a new paradigm or significant structural change, an Architecture Decision Record (ADR) must be submitted, reviewed, and merged into `docs/architecture/adr/`.

---

## 9. Future Compatibility

To ensure long-term viability, the current architecture must accommodate the following future roadmap items without requiring major refactoring:

### 9.1 Bulk Scan
Core analysis engines and data ingress points must operate on generator/iterator patterns (streaming data) rather than functions that return complete lists in memory. This ensures scalability when scanning enterprise-sized codebases.

### 9.2 SARIF Integration
Output formatting must be abstracted behind a standard `ReportGenerator` interface. This allows seamless plug-and-play addition of SARIF, JSON, CSV, and HTML exporters without touching the core detection logic.

### 9.3 Root-Cause Clustering
Internal data models for vulnerabilities and detections must carry stable, deterministic hashes/identifiers (based on file path, line number, and AST node type). This will enable future graph-based clustering algorithms to group related issues automatically.

### 9.4 Healing Proxy
Analysis results must strictly decouple "detection" from "remediation". Detection objects must capture sufficient structural context (e.g., AST nodes, exact byte offsets, surrounding token streams) so that a future remediation engine or active proxy can safely apply patches or block traffic dynamically.
