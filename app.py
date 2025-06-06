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

from flask import Flask, render_template, request, jsonify, Response 
import requests
import re
from dotenv import load_dotenv
import os
from taxii2client.v20 import Server
from stix2 import MemoryStore
import json
# from flask import Response
import pandas as pd

CACHE_FILE = "data/mitre_techniques.json"

app = Flask(__name__)

# # --- Mocked Data Fetch ---
# def fetch_otx_feed():
#     # Replace this URL with an actual API call or threat feed source
#     return [
#         {"id": 1, "content": "Malware detected at 45.77.33.89 with MD5 hash a5f3c6a11b03839d46af9fb43c97c188"},
#         {"id": 2, "content": "Phishing URL http://malicious.com/login found spreading via email"},
#         {"id": 3, "content": "Suspicious SHA256 hash: 44d88612fea8a8f36de82e1278abb02f"}
#     ]



load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

def fetch_otx_feed():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            feed = []
            for pulse in data.get("results", []):
                feed.append({
                    "id": pulse["id"],
                    "content": pulse.get("description", "") + " " + " ".join([i.get("indicator", "") for i in pulse.get("indicators", [])])
                })
            return feed
        else:
            print(f"[ERROR] OTX API Error: {response.status_code}")
            return []
    except Exception as e:
        print(f"[ERROR] Exception fetching OTX data: {e}")
        return []


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



def get_mitre_attack_techniques():
    server = Server('https://cti-taxii.mitre.org/taxii/')
    api_root = server.api_roots[0]
    collection = api_root.collections[0]

    try:
        # Add timeout parameter here
        stix_data = collection.get_objects(timeout=5)
        mem_store = MemoryStore(stix_data=stix_data['objects'])

        techniques = mem_store.query([
            {"type": "attack-pattern"}
        ])

        technique_map = {}
        for tech in techniques:
            technique_map[tech['id']] = {
                "name": tech['name'],
                "description": tech.get('description', ''),
                "external_id": next((e['external_id'] for e in tech['external_references'] if 'external_id' in e), '')
            }
        return technique_map

    except requests.exceptions.Timeout:
        print("[ERROR] Timeout while fetching MITRE ATT&CK data.")
        return {}

    except Exception as e:
        print(f"[ERROR] Exception in MITRE fetch: {e}")
        return {}
    
def get_cached_mitre_attack_techniques():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            print("[INFO] MITRE techniques loaded from cache.")
            return json.load(f)

    print("[INFO] Fetching techniques from MITRE TAXII server...")
    try:
        server = Server('https://cti-taxii.mitre.org/taxii/')
        api_root = server.api_roots[0]
        collection = api_root.collections[0]

        stix_data = collection.get_objects(timeout=5)
        mem_store = MemoryStore(stix_data=stix_data["objects"])

        techniques = mem_store.query([
            {"type": "attack-pattern"}
        ])

        technique_map = {}
        for tech in techniques:
            external_id = next(
                (e['external_id'] for e in tech['external_references'] if 'external_id' in e),
                None
            )
            if external_id:
                technique_map[external_id] = {
                    "name": tech['name'],
                    "description": tech.get("description", "")
                }

        # Save locally for future use
        with open(CACHE_FILE, "w") as f:
            json.dump(technique_map, f, indent=2)

        return technique_map

    except Exception as e:
        print(f"[ERROR] MITRE TAXII fetch failed: {e}")
        return {}
    

'''
Search IOC descriptions for technique names or IDs

Add a new field in the dashboard to show technique mappings

Future: match specific tools to techniques
'''

def map_ioc_to_techniques(ioc_entry, technique_map):
    keyword_mapping = {
        "powershell": "T1059.001",
        "base64": "T1027",
        "pastebin": "T1105",
        "github": "T1105",
        "cmd.exe": "T1059.003",
        "macro": "T1203",
        "vbs": "T1064",
        "mshta": "T1218.005",
        "rundll32": "T1218.011",
        "regsvr32": "T1218.010"
    }

    content = ' '.join(sum((ioc_entry.get(k, []) for k in ["ip", "url", "md5", "sha256"]), [])).lower()

    
    matched = set()
    for keyword, tid in keyword_mapping.items():
        if keyword in content and tid in technique_map:
            match = f"{tid}: {technique_map[tid]['name']}"
            matched.add(match)

    return list(matched)



@app.route('/')
def index():
    raw_feed = fetch_otx_feed()
    parsed_iocs = extract_iocs(raw_feed)
    technique_map = get_cached_mitre_attack_techniques()

    # 🛠️ Add this block here
    technique_descriptions = {
        tid: data["description"]
        for tid, data in technique_map.items()
    }

    for ioc in parsed_iocs:
        ioc["techniques"] = map_ioc_to_techniques(ioc, technique_map)

    # ✅ Pass technique_descriptions to template
    return render_template(
        'dashboard.html',
        iocs=parsed_iocs,
        technique_descriptions=technique_descriptions
    )


@app.route('/export.csv')
def export_csv():
    raw_feed = fetch_otx_feed()
    parsed_iocs = extract_iocs(raw_feed)
    technique_map = get_cached_mitre_attack_techniques()

    for ioc in parsed_iocs:
        ioc["techniques"] = map_ioc_to_techniques(ioc, technique_map)

    data = []
    for ioc in parsed_iocs:
        data.append({
            "ID": ioc["id"],
            "IPs": ', '.join(ioc["ip"]),
            "URLs": ', '.join(ioc["url"]),
            "MD5 Hashes": ', '.join(ioc["md5"]),
            "SHA256 Hashes": ', '.join(ioc["sha256"]),
            "MITRE Techniques": ', '.join(ioc["techniques"])
        })

    df = pd.DataFrame(data)
    csv_data = df.to_csv(index=False)

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=iocs_export.csv"}
    )

if __name__ == '__main__':
    app.run(debug=True)
