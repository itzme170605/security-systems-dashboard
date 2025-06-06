# security-systems-dashboard
A simulation dashboard for a multi-site security system using Flask, React, and SQLite

# Cyber Threat Intelligence Dashboard — Design Document (v0.1)

---

###  Overview
The **Cyber Threat Intelligence Dashboard** is a lightweight Flask-based web application designed to ingest open-source cyber threat feeds, extract Indicators of Compromise (IOCs), and present them in a human-readable format. This tool is intended for cybersecurity analysts, researchers, and blue teams to improve threat visibility and awareness.

---

### Objectives
- Automate the parsing of publicly available threat data
- Extract and display relevant IOCs (IPs, hashes, URLs)
- Provide an interactive dashboard for analysis
- Map known IOCs to MITRE ATT&CK techniques (future)
- Integrate with external feeds/APIs like OTX, VirusTotal, AbuseIPDB (future)

---

### Architecture

**Tech Stack**
- **Backend**: Flask (Python)
- **Frontend**: HTML/CSS (Jinja2 templates)
- **Deployment (optional)**: Render, Railway, or Docker

**Directory Structure**
```
/threat-intel-dashboard
├── app.py                  # Flask backend
├── templates/
│   └── dashboard.html      # HTML dashboard
├── requirements.txt        # Python dependencies
├── README.md
└── venv/                   # Virtual environment (excluded from version control)
```

---

### Core Components

| Component        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `fetch_otx_feed()` | Mocked or real-time ingestion of threat data (from OTX, etc.)               |
| `extract_iocs()`   | Uses regular expressions to extract IOCs (IPs, URLs, hashes)               |
| `dashboard.html`   | Frontend display of structured IOC data                                    |
| MITRE Mapping     | Future enhancement to classify IOCs using ATT&CK framework                 |

---

###  Features (Phase 1 – Complete)
- Mock IOC feed ingestion
- IOC extraction: IP, URL, MD5, SHA256
- Dynamic dashboard rendering via Jinja2 template

---

### Upcoming (Phase 2)
- Replace mock data with **live feeds** (e.g., OTX pulse API)
- Add MITRE ATT&CK mapping logic
- Enable **export to CSV/PDF**
- Set up basic alerting (e.g., Slack/email webhook)
- Deploy publicly (Render or Docker)

---

### Security Considerations
- Input/output sanitization
- Logging for suspicious payloads (future)
- API rate limiting and key handling (for real feeds)

---

### Roadmap
| Version | Features                                                                 |
|---------|--------------------------------------------------------------------------|
| 0.1     | IOC parsing from mocked feed, display in dashboard                       |
| 0.2     | Live feed integration, MITRE mapping                                     |
| 0.3     | Authentication, export features, dark mode UI toggle                     |
| 1.0     | Fully deployable platform with alerting and CI/CD                        |

### Just some notes 
PowerShell-based obfuscation → T1059.001

Base64 + script execution → T1027

Domains like pastebin.com, github.com/raw/ → common in data exfiltration or staging

We’ll append a new column: Mapped Technique(s)