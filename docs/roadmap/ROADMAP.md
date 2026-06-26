# Sentin4e Product Roadmap

This document outlines the strategic, long-term vision for Sentin4e. As Sentin4e evolves from a single-target HTTP scanner into a flagship enterprise security tool, we must prioritize building a stable architectural foundation before introducing advanced, experimental capabilities. 

---

## v1.x: Foundation (CI/CD & Scale)

**Theme:** Automation and Integrations
**Goals:** Transform Sentin4e from a manual utility into a scalable, pipeline-ready tool that integrates seamlessly into DevSecOps workflows.

### Planned Features
* **Batch Processing & Asset Discovery Integration:** Support for bulk scanning (`-i targets.txt`) via asynchronous HTTP requests.
* **SARIF Output Generation:** Outputting reports in the Static Analysis Results Interchange Format (SARIF) for native integration into GitHub Advanced Security and GitLab CI.
* **Webhook Response Callbacks:** Instantly pushing JSON scan results to external SIEMs, Slack, or webhooks upon completion.

### Why these features belong here
Before Sentin4e can do advanced analysis, it must be able to handle hundreds of targets concurrently and report findings in industry-standard formats. This builds the user base among DevSecOps engineers.

* **Dependencies:** None.
* **Complexity:** Medium (requires refactoring the networking layer to support `asyncio`/`httpx`).
* **User Impact:** Massive. Unlocks enterprise automation and bulk bug-bounty scanning.

---

## v2.x: Advanced Analysis (Penetration Testing & Evasion)

**Theme:** Evasion and Deep Reconnaissance
**Goals:** Provide red teamers and security researchers with advanced tools to bypass modern WAFs and map hidden infrastructure.

### Planned Features
* **TLS Fingerprint Shifting (JA3/JA4 Spoofing):** Dynamically spoofing the TLS handshake fingerprints of standard web browsers to bypass WAFs that block default CLI tooling.
* **Shadow API Correlator:** Statistically analyzing header fingerprints across bulk scans to automatically flag legacy or shadow infrastructure (e.g., detecting an old Tomcat server among modern Nginx APIs).
* **Origin Unveiling & WAF Bypass Engine:** Using historical IP correlation and SNI routing manipulation to bypass CDN protections and hit origin servers directly.

### Why these features belong here
With bulk scanning established in v1.x, v2.x focuses on ensuring those scans actually succeed against heavily defended perimeters (Cloudflare, AWS WAF).

* **Dependencies:** Requires the v1.x asynchronous networking engine.
* **Complexity:** High (requires custom `urllib3` adapters or low-level TLS libraries).
* **User Impact:** High. Gives analysts capabilities usually reserved for proprietary offensive tooling.

---

## v3.x: Enterprise & Collaboration (Alert Fatigue & Remediation)

**Theme:** Noise Reduction and Actionable Fixes
**Goals:** Stop dumping thousands of alerts on DevOps teams. Instead, identify the root cause and provide the exact code required to fix it.

### Planned Features
* **Infrastructure Root-Cause Clustering:** Using heuristics to group hundreds of identical alerts into a single root-cause infrastructural error (e.g., "AWS API Gateway misconfiguration affecting 50 subdomains").
* **Self-Healing IaC Patch Generation:** Generating Terraform (`.tf`) or Kubernetes (`.yaml`) snippets that perfectly remediate the detected missing headers.

### Why these features belong here
Advanced scanning (v2.x) will generate massive amounts of data. v3.x focuses on aggregating that data into human-readable, actionable intelligence.

* **Dependencies:** Requires the Shadow API correlator and robust SARIF output.
* **Complexity:** High (requires complex data clustering and IaC templating engines).
* **User Impact:** High. Turns security findings into immediate engineering tickets with the solution already provided.

---

## v4.x: Platform & Ecosystem (Active Defense)

**Theme:** Real-Time Mitigation and State Analysis
**Goals:** Transition Sentin4e from a passive reporting tool into an active defense proxy and state-machine fuzzer.

### Planned Features
* **Sentin4e Healing Proxy:** A long-running daemon mode (`sentin4e proxy`) that acts as a local reverse proxy, dynamically injecting missing security headers into insecure legacy backends in real-time.
* **Header Fuzzing for State-Machine Mapping:** Sending malformed or contradictory headers to discover cache poisoning vulnerabilities, hidden WAF rules, and reverse-proxy desyncs.

### Why these features belong here
These are pinnacle features that drastically alter the architecture of the tool, moving it from a CLI script to a continuous service. 

* **Dependencies:** Requires a highly mature, heavily tested codebase with absolute zero-false-positive detection logic.
* **Complexity:** Very High (managing proxy state, streaming bodies, and complex HTTP anomalies).
* **User Impact:** Transformational. Allows immediate mitigation of zero-day architectural flaws without touching application code.

---

## Future Research & Rejected Features

The following features were considered but are either too experimental for the core roadmap or conflict with Sentin4e's identity as a lightweight, lightning-fast CLI tool.

### 1. Ephemeral Sandbox Validation (Headless Browser Proofs)
* **Status:** Rejected (for core CLI).
* **Reasoning:** Spinning up a headless Chromium instance to prove DOM XSS or Clickjacking would ruin the performance and lightweight footprint of a Python CLI. This feature belongs in a heavy DAST platform (like Burp Suite), not a fast header analyzer.

### 2. Time-Travel Drift Analysis (Historical Profiling)
* **Status:** Moved to Future Research.
* **Reasoning:** Relying on the Wayback Machine or Censys API for historical headers introduces massive external dependencies, paywalls, and API rate limits. It is difficult to guarantee reliability in an open-source CLI. This may be explored later as an optional plugin rather than a core feature.

### 3. Full Terminal User Interface (TUI)
* **Status:** Moved to Future Research.
* **Reasoning:** While visually impressive, building and maintaining a complex TUI framework diverts engineering resources away from the core detection engine. Command-line flags and SARIF output provide more immediate value to power users.
