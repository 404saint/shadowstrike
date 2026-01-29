# ShadowStrike

**ShadowStrike** is a passive attack surface and Shadow IT intelligence engine designed to help security teams understand *what is exposed*, *why it matters*, and *how risky it is* — without performing any active scanning.

It works in **two modes**:
- **Online mode** using live Shodan data
- **Offline mode** using user‑supplied JSON datasets

Once assets are loaded, ShadowStrike applies the same analysis pipeline to both modes, producing **explainable risk scores**, **Shadow IT indicators**, and **professional reports** (JSON, Markdown, HTML).

---

## Why ShadowStrike Exists

Modern organizations often lose visibility over:
- Cloud assets spun up outside official processes
- Internet‑exposed admin panels and databases
- High‑risk services accidentally left public
- Shadow IT infrastructure hiding in plain sight

ShadowStrike was built to answer one question:

> **“If I were an attacker, what would I see — and which assets would matter most?”**

---

## What ShadowStrike Does

For each discovered asset, ShadowStrike:

- Categorizes the exposed service (remote access, admin panel, database, etc.)
- Identifies high‑risk internet‑facing services
- Detects lack of transport security (TLS)
- Flags potential Shadow IT using hostname and certificate mismatches
- Assigns a **risk score (0–10)** with confidence
- Explains *why* each asset is risky
- Generates clean, shareable reports

All analysis is **passive**. No exploitation. No scanning.

---

## Features

- Online mode (Live Shodan API)
- Offline mode (Any JSON dataset with asset data)
- Shadow IT detection with confidence scoring
- Explainable risk scoring
- Asset deduplication with first/last seen timestamps
- Report generation:
  - JSON (machine‑readable)
  - Markdown (documentation / audits)
  - HTML (executive‑friendly)

---

## Installation & Usage

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/shadowstrike.git
cd shadowstrike
````

---

### 2. Install requirements

```bash
pip install shodan
```

> Python 3.9+ recommended

---

### 3. (Optional) Set Shodan API key — Online Mode only

If you want to use **online mode**, export your paid Shodan API key:

```bash
export SHODAN_API_KEY="YOUR_API_KEY"
```

If you don’t have a paid key, **offline mode works without Shodan**.

---

### 4. Run ShadowStrike

```bash
python shadowstrike.py
```

You will be guided interactively.

---

## Execution Modes

### Online Mode (Live Shodan)

Select:

```
1) Online (Live Shodan API)
```

You may provide:

* Organization name (e.g. `Google`)
* ASN (e.g. `AS15169`)

ShadowStrike will pull live Shodan data and analyze it.

> Requires a paid Shodan API plan.

---

### Offline Mode (JSON Dataset)

Select:

```
2) Offline (Load JSON dataset)
```

Provide the path to a JSON file containing asset data.

This allows you to:

* Analyze previously collected data
* Work in restricted environments
* Test safely without API limits

ShadowStrike treats offline data exactly like live data.

---

## Report Generation

After analysis completes, choose a report format:

```
1) JSON
2) Markdown
3) HTML
```

The report will be saved in the current directory with a UTC timestamp.

Examples:

```
shadowstrike_results_20260129_124057.json
shadowstrike_results_20260129_124057.md
shadowstrike_results_20260129_124057.html
```

---

## Example Output (Per Asset)

Each asset includes:

* Service category
* Exposure findings
* Shadow IT detection (with confidence)
* Risk score (0–10)
* Risk reasoning
* Risk confidence

This makes the output suitable for:

* Technical teams
* Security leadership
* Documentation and audits

---

## Ethical Use & Disclaimer

ShadowStrike is a **defensive, passive analysis tool**.

* No active scanning
* No exploitation
* No brute‑forcing

Use only on infrastructure you own or are authorized to analyze.

---

## License

MIT License

```
