# ThreatSight

### Detect. Analyze. Protect.

**Developed by Dreavyn**

---

## Overview

ThreatSight is a cybersecurity-focused phishing detection and brand impersonation analysis platform developed in Python.

The application analyzes URLs for phishing indicators, detects potential brand impersonation attempts, assigns risk scores, categorizes threats, and generates scan history reports through an interactive desktop interface.

Designed as a cybersecurity portfolio project, ThreatSight combines explainable threat analysis with a modern graphical user interface built using CustomTkinter.

---

## Features

- URL phishing analysis
- Brand impersonation detection
- Lookalike domain detection
- Suspicious keyword identification
- IP-based URL detection
- Risk scoring system
- Threat confidence classification
- Threat categorization
- Whitelist verification
- CSV report generation
- Scan history dashboard
- Modern CustomTkinter desktop interface
- Explainable threat reasoning

---

## Tech Stack

- Python 3.13
- CustomTkinter
- RapidFuzz
- CSV
- Regex
- urllib

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Anonadvait/ThreatSight.git
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python main.py
```

## Application Capabilities

ThreatSight can:

- Analyze URLs for phishing indicators
- Detect suspicious keywords commonly used in phishing campaigns
- Detect brand impersonation attempts
- Identify lookalike domains
- Detect IP-based URLs
- Assign risk scores
- Categorize threats
- Generate scan history reports
- Provide explainable threat analysis

---

## Threat Categories

| Category | Description |
|-----------|------------|
| Trusted / Safe | Verified trusted domains |
| Credential Theft | Suspicious login or credential harvesting indicators |
| Brand Impersonation | Domains attempting to imitate legitimate brands |
| Suspicious Infrastructure | URLs using direct IP addresses |
| General Suspicious Activity | Other suspicious behaviors |

---

## Future Improvements

- VirusTotal API integration
- PDF security report export
- Advanced threat intelligence feeds
- Machine learning-based phishing classification
- URL reputation database
- Dark/Light mode switching

---

## Author

**Dreavyn**

ThreatSight v1.0