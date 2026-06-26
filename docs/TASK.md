# Sentin4e Development Tasks

This document outlines the step-by-step development roadmap for Sentin4e, broken down by target versions. All tasks must adhere to the engineering standards and architectural principles defined in [SPEC.md](file:///c:/PROJECT/sentin4e/docs/SPEC.md).

## v0.1.0: Foundation & Scaffolding
**Goal:** Establish the project structure, tooling, and basic CLI entry point.
- [x] Initialize Python project (Python 3.10+) emphasizing minimal dependencies.
- [x] Configure code quality tools (`mypy --strict`, modern linting/formatting).
- [x] Setup initial CI/CD pipelines for testing across Linux, Windows, and macOS.
- [x] Implement the base `Sentin4eError` exception class and global error handling scaffolding.
- [x] Create the basic CLI entry point using `typer` and `rich`.
- [x] Setup standard `logging` configured with `rich.logging.RichHandler`.
- [x] Create initial documentation (`README.md`, `docs/usage.md`).

## v0.2.0: Core Architecture & Data Models
**Goal:** Implement the core business logic abstractions and immutable data models.
- [ ] Define immutable data models using `dataclasses(frozen=True)` or Pydantic for core domain objects (e.g., `ScanTarget`, `DetectionResult`).
- [ ] Implement the configuration management system (Priority: CLI args > Env vars > TOML).
- [ ] Define Abstract Base Classes (ABCs) or Protocols for the plugin/module architecture (`BaseAnalyzer`, `ReportGenerator`).
- [ ] Implement a secure, OS-agnostic file discovery and path handling utility (`pathlib` based).
- [ ] Write unit tests for data models and configuration parser (Target: 85% coverage).

## v0.3.0: Module Engine & Concurrency
**Goal:** Build the engine that runs analysis modules, incorporating concurrency and safe boundaries.
- [ ] Implement the core execution engine that safely discovers and loads plugins.
- [ ] Integrate `asyncio` for I/O-bound operations and `multiprocessing` for CPU-bound tasks.
- [ ] Add configurable global and per-task timeouts for all engine operations.
- [ ] Build a "dummy" or "diagnostic" analyzer plugin to validate the engine architecture.
- [ ] Ensure the engine fails securely and recovers gracefully from individual plugin crashes (no raw stack traces).

## v0.4.0: Output Formats & Rich UI
**Goal:** Polish the terminal experience and abstract the reporting layer.
- [ ] Enhance the Typer CLI with beautiful help text, progress bars, and status spinners using Rich.
- [ ] Implement the `ReportGenerator` abstraction for output formatting.
- [ ] Create a terminal-optimized stdout report generator.
- [ ] Implement a machine-readable JSON report generator.
- [ ] Add integration tests for end-to-end CLI workflows.

## v0.5.0: Initial Security Modules
**Goal:** Implement the first set of real security analysis capabilities.
- [ ] Develop the first functional Static Analysis module.
- [ ] Develop the first functional dynamic/introspection module.
- [ ] Implement strict zero-trust input validation and sanitization for module parameters.
- [ ] Write dedicated tests for security edge cases (e.g., malformed inputs, large files, path traversal attempts).

## v1.0.0: Stable Release & Hardening
**Goal:** Finalize the v1.0.0 release candidate, complete audits, and publish.
- [ ] Execute a mandatory one-week feature freeze.
- [ ] Conduct a manual security code review of the entire codebase.
- [ ] Run automated SAST/DAST and dependency vulnerability audits.
- [ ] Finalize all public APIs and CLI flags (must remain backwards-compatible post-v1.0.0).
- [ ] Complete all user-facing documentation and architectural decision records (ADRs).
- [ ] Setup the PyPI release pipeline via Trusted OIDC Publishers.

## v1.1.0+: Advanced Capabilities (Future Roadmap)
**Goal:** Implement the future compatibility features defined in the specification.
- [ ] Refactor ingress points to support Bulk Scanning (generator/iterator streaming for 10,000+ files).
- [ ] Implement the SARIF `ReportGenerator` for enterprise CI/CD integration.
- [ ] Add stable, deterministic hashing to detection data models for Root-Cause Clustering.
- [ ] Prototype the Healing Proxy concept (decoupling detection from active remediation).
