# Cyber Threat Intelligence Dashboard (v0.1)

"""
This Flask-based app ingests open-source threat intelligence feeds,
parses Indicators of Compromise (IOCs), maps them to MITRE ATT&CK techniques,
and presents them on a web dashboard.

Core Features (Phase 1):
- Ingest threat feed (e.g., JSON from AlienVault OTX)
- Parse and extract IOCs (IPs, URLs, hashes)
- Display parsed data in a web interface
- Basic MITRE technique mapping (mocked for now)
"""

from flask import Flask, render_template, request, jsonify
import requests
import re

app = Flask(__name__)

# --- Mocked Data Fetch ---
def fetch_otx_feed():
    # Replace this URL with an actual API call or threat feed source
    return [
        {"id": 1, "content": "Malware detected at 45.77.33.89 with MD5 hash a5f3c6a11b03839d46af9fb43c97c188"},
        {"id": 2, "content": "Phishing URL http://malicious.com/login found spreading via email"},
        {"id": 3, "content": "Suspicious SHA256 hash: 44d88612fea8a8f36de82e1278abb02f"}
    ]

# --- IOC Extraction ---
def extract_iocs(feed):
    iocs = []
    ip_regex = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
    url_regex = re.compile(r'https?://[\w./-]+')
    md5_regex = re.compile(r'\b[a-fA-F0-9]{32}\b')
    sha256_regex = re.compile(r'\b[a-fA-F0-9]{64}\b')

    for entry in feed:
        content = entry['content']
        iocs.append({
            'id': entry['id'],
            'ip': ip_regex.findall(content),
            'url': url_regex.findall(content),
            'md5': md5_regex.findall(content),
            'sha256': sha256_regex.findall(content)
        })
    return iocs

@app.route('/')
def index():
    raw_feed = fetch_otx_feed()
    parsed_iocs = extract_iocs(raw_feed)
    return render_template('dashboard.html', iocs=parsed_iocs)

if __name__ == '__main__':
    app.run(debug=True)
