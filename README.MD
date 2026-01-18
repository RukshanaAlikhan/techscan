# TechScan 🔍

A security-focused technology stack analyzer that detects technologies, identifies versions, and assesses vulnerability risks.

## What it does

1. **Detects** - Identifies technologies used by a website (frameworks, CMS, libraries, servers)
2. **Versions** - Extracts version information where possible
3. **Analyzes** - Checks for known vulnerabilities (CVEs)
4. **Scores** - Provides an overall security risk assessment

## Project Structure

```
techscan/
├── techscan/
│   ├── __init__.py
│   ├── detector.py      # Tech detection logic
│   ├── version.py       # Version extraction
│   ├── vulns.py         # Vulnerability lookup
│   └── scoring.py       # Risk scoring
├── signatures/
│   └── technologies.json # Tech fingerprints
├── main.py              # CLI entry point
├── requirements.txt
└── README.md
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py https://example.com
```

## Learning Goals

This project teaches:
- HTTP requests and response parsing
- Pattern matching with regex
- Working with APIs (NVD/CVE)
- JSON data handling
- Basic security concepts