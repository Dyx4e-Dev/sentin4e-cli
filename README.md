# GuardCLI

A defensive cybersecurity CLI tool that audits HTTP security posture of websites.

## Architecture

```
guardcli/
├── pyproject.toml
├── src/
│   └── guardcli/
│       ├── cli.py            # Primary Typer app entrypoint
│       ├── exceptions.py     # Custom error handling
│       ├── scanner/          # Security checks logic
│       │   ├── headers.py
│       │   ├── tls.py
│       │   ├── score.py
│       │   └── weights.py
│       ├── models/           # Pydantic data models
│       │   └── report.py
│       ├── output/           # Renderers and exporters
│       │   ├── terminal.py
│       │   ├── json_export.py
│       │   └── serializers.py
│       └── utils/            # Shared utilities
│           ├── validator.py
│           └── logger.py
└── tests/                    # Pytest suite
```

## Setup Instructions

Ensure you have Python 3.11+.

```bash
git clone <repo>
cd guardcli
pip install -e .[dev]
```

## Running Examples

```bash
# Full security scan
guard scan https://example.com

# Inspect headers only
guard headers https://example.com

# Export JSON report
guard export https://example.com -o report.json

# Check system health
guard doctor

# Version
guard version
```

## Future Roadmap

- Advanced TLS cipher suite analysis
- Authentication header checks (CORS, Set-Cookie attributes)
- Multi-target bulk scanning
- CI/CD integration pipelines
