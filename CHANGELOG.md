# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-06-23

### Added
- Initial release of GuardCLI.
- Added `scan` command for full security checks.
- Added `headers` command for quick inspection.
- Added `export` command for JSON reports.
- Added `doctor` command for system checks.
- Implemented core security checks: HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server Disclosure.
- Built risk calculation engine with severity weights.
- Setup TLS validation with retries and verbose logging.
