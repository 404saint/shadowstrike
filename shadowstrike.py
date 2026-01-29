# ShadowStrike – Passive Attack Surface & Shadow IT Intelligence Engine (Online + Offline)
# Author: RUGERO Tesla (404saint)
# License: MIT

"""
ShadowStrike is a passive attack surface and Shadow IT intelligence engine.
It supports:
- Online mode (live Shodan API)
- Offline mode (user-supplied JSON datasets)

The analysis pipeline is source-agnostic: online and offline assets
are processed identically once loaded.
"""

import os
import json
import shodan
from datetime import datetime, timezone

# =========================
# CONFIGURATION
# =========================
HIGH_RISK_PORTS = {3389, 445, 21, 23, 5900, 6379, 9200, 8080, 8443}
MAX_RISK_SCORE = 10.0

SERVICE_CATEGORIES = {
    "remote_access": {3389, 22, 5900},
    "admin_panel": {8080, 8443, 10000},
    "database": {3306, 5432, 6379, 9200},
    "file_sharing": {21, 445},
}

# =========================
# SHODAN CLIENT (ONLINE MODE)
# =========================
class ShodanClient:
    def __init__(self):
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise RuntimeError("SHODAN_API_KEY environment variable not set")
        self.client = shodan.Shodan(api_key)

    def search(self, org=None, asn=None):
        query = []
        if org:
            query.append(f'org:"{org}"')
        if asn:
            query.append(f'asn:{asn}')

        q = " ".join(query)
        print(f"[+] Shodan query: {q}")

        results = self.client.search(q)
        assets = []

        for match in results.get("matches", []):
            assets.append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "service": match.get("product"),
                "version": match.get("version"),
                "transport": match.get("transport"),
                "hostnames": match.get("hostnames") or [],
                "ssl": match.get("ssl"),
                "timestamp": match.get("timestamp"),
                "raw": match
            })
        return assets

# =========================
# OFFLINE MODE LOADER
# =========================
def load_offline_assets(path):
    if not os.path.exists(path):
        raise FileNotFoundError("Offline JSON file not found")

    with open(path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Offline dataset must be a list of asset objects")

    return data

# =========================
# ASSET DEDUPLICATION
# =========================
def deduplicate_assets(assets):
    deduped = {}

    for a in assets:
        key = f"{a.get('ip')}:{a.get('port')}"
        ts = a.get("timestamp")

        if key not in deduped:
            deduped[key] = a
            deduped[key]["first_seen"] = ts
            deduped[key]["last_seen"] = ts
        else:
            deduped[key]["last_seen"] = ts

    return list(deduped.values())

# =========================
# EXPOSURE ANALYSIS
# =========================
def categorize_service(port):
    for category, ports in SERVICE_CATEGORIES.items():
        if port in ports:
            return category
    return "other"


def analyze_exposure(asset):
    findings = []

    if asset.get("port") in HIGH_RISK_PORTS:
        findings.append("High-risk internet-facing service")

    if not asset.get("ssl"):
        findings.append("No TLS detected")

    return findings

# =========================
# SHADOW IT DETECTION
# =========================
def analyze_shadow_it(asset, org):
    signals = []
    confidence = 0.0

    for hostname in asset.get("hostnames", []):
        if org and org.lower() not in hostname.lower():
            signals.append("Hostname does not match organization naming")
            confidence += 0.3

    ssl = asset.get("ssl") or {}
    cert = ssl.get("cert", {})
    cn = cert.get("subject", {}).get("CN")

    if cn and org and org.lower() not in cn.lower():
        signals.append("TLS Common Name mismatch")
        confidence += 0.4

    detected = confidence >= 0.4
    confidence = min(confidence, 1.0)

    return {
        "detected": detected,
        "confidence": round(confidence, 2),
        "signals": signals
    }

# =========================
# RISK SCORING
# =========================
def calculate_risk(asset):
    score = 0.0
    reasons = []

    category = asset.get("service_category")

    if category == "remote_access":
        score += 4.0
        reasons.append("Remote access service exposed")
    elif category == "admin_panel":
        score += 3.0
        reasons.append("Administrative interface exposed")
    elif category == "database":
        score += 3.5
        reasons.append("Database service exposed")
    elif category == "file_sharing":
        score += 2.5
        reasons.append("File sharing service exposed")

    if asset.get("port") in HIGH_RISK_PORTS:
        score += 2.5
        reasons.append("High-risk service exposed")

    if asset.get("exposure"):
        score += len(asset["exposure"]) * 1.2
        reasons.extend(asset["exposure"])

    shadow = asset.get("shadow_it", {})
    if shadow.get("detected"):
        score += shadow.get("confidence", 0) * 3
        reasons.extend(shadow.get("signals", []))

    if asset.get("version"):
        score += 1.0
        reasons.append("Service version disclosed")

    score = min(score, MAX_RISK_SCORE)
    confidence = min(1.0, score / MAX_RISK_SCORE)

    return round(score, 1), list(set(reasons)), round(confidence, 2)

# =========================
# REPORT GENERATION
# =========================
def generate_report(assets, fmt):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    high = sum(1 for a in assets if a["risk_score"] >= 7)
    medium = sum(1 for a in assets if 4 <= a["risk_score"] < 7)
    low = sum(1 for a in assets if a["risk_score"] < 4)

    summary = (
        f"Total Assets: {len(assets)}\n"
        f"High Risk: {high}\n"
        f"Medium Risk: {medium}\n"
        f"Low Risk: {low}\n"
    )

    if fmt == "json":
        out = f"shadowstrike_results_{ts}.json"
        with open(out, "w") as f:
            json.dump({"summary": summary, "assets": assets}, f, indent=2)

    elif fmt == "md":
        out = f"shadowstrike_results_{ts}.md"
        with open(out, "w") as f:
            f.write("# ShadowStrike Report\n\n")
            f.write(f"Generated (UTC): {ts}\n\n")
            f.write("## Executive Summary\n\n")
            f.write(summary + "\n")

            for a in assets:
                f.write(f"## {a['ip']}:{a['port']}\n")
                f.write(f"**Service:** {a.get('service')}\n\n")
                f.write(f"**Category:** {a.get('service_category')}\n\n")
                f.write(f"**Risk Score:** {a['risk_score']} (Confidence: {a['risk_confidence']})\n\n")
                for r in a["risk_reasons"]:
                    f.write(f"- {r}\n")
                f.write("\n---\n\n")

    elif fmt == "html":
        out = f"shadowstrike_results_{ts}.html"
        with open(out, "w") as f:
            f.write("<html><head><title>ShadowStrike Report</title></head><body>")
            f.write(f"<h1>ShadowStrike Report</h1><p>Generated (UTC): {ts}</p>")
            f.write("<h2>Executive Summary</h2><pre>" + summary + "</pre>")
            for a in assets:
                f.write(f"<h3>{a['ip']}:{a['port']}</h3>")
                f.write(f"<p><b>Service:</b> {a.get('service')}<br>")
                f.write(f"<b>Category:</b> {a.get('service_category')}<br>")
                f.write(f"<b>Risk Score:</b> {a['risk_score']} (Confidence: {a['risk_confidence']})</p>")
                f.write("<ul>")
                for r in a["risk_reasons"]:
                    f.write(f"<li>{r}</li>")
                f.write("</ul>")
            f.write("</body></html>")

    else:
        raise ValueError("Unsupported report format")

    print(f"[+] Results written to {out}")

# =========================
# MAIN
# =========================
def main():
    print("\n=== ShadowStrike ===")

    print("\nSelect execution mode:")
    print("1) Online (Live Shodan API)")
    print("2) Offline (Load JSON dataset)")
    mode = input("Choice: ").strip()

    assets = []
    org = None

    if mode == "1":
        org = input("Organization (blank to skip): ").strip() or None
        asn = input("ASN (blank to skip): ").strip() or None
        try:
            client = ShodanClient()
            assets = client.search(org=org, asn=asn)
        except Exception as e:
            print(f"[!] Online mode failed: {e}")
            return

    elif mode == "2":
        path = input("Path to offline JSON file: ").strip()
        try:
            assets = load_offline_assets(path)
        except Exception as e:
            print(f"[!] Offline load failed: {e}")
            return

    else:
        print("Invalid mode selection")
        return

    if not assets:
        print("[!] No assets loaded")
        return

    assets = deduplicate_assets(assets)

    for asset in assets:
        asset["service_category"] = categorize_service(asset.get("port"))
        asset["exposure"] = analyze_exposure(asset)
        asset["shadow_it"] = analyze_shadow_it(asset, org)
        risk, reasons, confidence = calculate_risk(asset)
        asset["risk_score"] = risk
        asset["risk_reasons"] = reasons
        asset["risk_confidence"] = confidence

    print(f"\n[+] Analysis complete — {len(assets)} assets processed")

    print("\nSelect report format:")
    print("1) JSON")
    print("2) Markdown")
    print("3) HTML")
    choice = input("Choice: ").strip()
    fmt = {"1": "json", "2": "md", "3": "html"}.get(choice)

    if not fmt:
        print("Invalid report format")
        return

    generate_report(assets, fmt)


if __name__ == "__main__":
    main()
