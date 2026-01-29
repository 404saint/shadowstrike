# ShadowStrike

**Passive Attack Surface & Shadow IT Intelligence Engine**

ShadowStrike is a security intelligence tool designed to analyze internet‑exposed assets using either live Shodan data or offline JSON datasets.  
It helps identify high‑risk services, misconfigurations, and potential Shadow IT with explainable risk scoring.

---

## ✨ Features

- Online mode (Live Shodan API)
- Offline mode (User‑supplied JSON datasets)
- Shadow IT detection with confidence scoring
- Service categorization & exposure analysis
- Risk scoring with explainable reasons
- Multi‑format reporting:
  - JSON
  - Markdown
  - HTML

---

## 🧠 Use Cases

- Attack surface discovery
- Shadow IT identification
- Passive reconnaissance
- Blue team risk assessments
- Security research & education

---

## 🚀 Usage

### Run the tool
```bash
python shadowstrike.py
````

### Execution Modes

* **Online**: Requires a paid Shodan API key
* **Offline**: Load JSON datasets from any source

### Report Formats

* JSON
* Markdown
* HTML

---

## 🔐 Shodan API Setup (Online Mode)

Set your API key as an environment variable:

```bash
export SHODAN_API_KEY="YOUR_API_KEY"
```

---

## 📄 License

MIT License

---

## ⚠️ Disclaimer

ShadowStrike is a **passive analysis tool**.
It does **not** perform exploitation or active scanning.

Use responsibly.

```
