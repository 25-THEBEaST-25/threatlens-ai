# 🛡️ ThreatLens AI

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-App-FF4B4B?logo=streamlit)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--Powered-10A37F?logo=openai)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Threat%20Intelligence](https://img.shields.io/badge/Threat%20Intel-AbuseIPDB-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey)

An AI-powered cybersecurity investigation assistant that transforms raw security logs into actionable incident investigations, attack narratives, analyst recommendations, and downloadable case reports.

---

# 📖 Overview

ThreatLens AI is designed to simplify security investigations by automatically parsing multiple log formats, detecting malicious activities, enriching findings with threat intelligence, and generating AI-assisted investigation reports.

Instead of presenting isolated alerts, ThreatLens AI reconstructs the complete attack timeline, helping analysts understand what happened, why it happened, and what actions should be taken next.

---

# ✨ Features

- 📂 Multi-format log ingestion
- 🔍 Automated threat detection
- 🤖 AI-generated attack narratives
- 📊 Interactive SOC dashboard
- 🛡️ Threat intelligence enrichment
- 📄 Incident report generation
- 📋 Case management workflow
- 💻 Analyst command suggestions
- ⚙️ False positive reduction using allowlists
- 📥 Downloadable investigation reports

---

# 🚀 What Makes ThreatLens AI Different

### 🧠 Attack Story Mode

Transforms scattered log events into a chronological attack narrative for easier investigations.

---

### 🛠️ SOC Command Assistant

Suggests Linux investigation commands such as:

- grep
- journalctl
- last
- lastb
- who
- netstat
- ss

to help analysts validate suspicious activity.

---

### 📂 Case Workflow

Track investigations with:

- Case Owner
- Investigation Status
- Analyst Notes
- Risk Score
- Downloadable Case Reports

---

### 🌍 Threat Intelligence Layer

Supports:

- Local behavioral enrichment
- Optional AbuseIPDB lookups
- Reputation-based scoring

---

### 🎯 False Positive Controls

Reduce noisy alerts using:

- Trusted IP allowlists
- Internal network exclusions
- Trusted User-Agent filtering

---

# 🔎 Detection Coverage

| Threat | Detection |
|----------|:---------:|
| Brute Force Authentication | ✅ |
| Credential Stuffing | ✅ |
| Successful Login After Failures | ✅ |
| Admin Endpoint Probing | ✅ |
| Directory Traversal Attempts | ✅ |
| Scanner User Agents | ✅ |
| Suspicious Endpoint Enumeration | ✅ |
| Threat Intelligence Enrichment | ✅ |

---

# 🏗️ Architecture

```text
                    Security Logs
                           │
                           ▼
                 Log Parsing Engine
                           │
                           ▼
                  Detection Pipeline
        ┌──────────────────────────────────┐
        │ Brute Force Detection            │
        │ Credential Stuffing              │
        │ Endpoint Probing                 │
        │ Scanner Detection                │
        └──────────────────────────────────┘
                           │
                           ▼
             Threat Intelligence Layer
           (Behavior + AbuseIPDB Lookup)
                           │
                           ▼
               AI Investigation Engine
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
     Attack Story                 Analyst Commands
            │                             │
            └──────────────┬──────────────┘
                           ▼
                  Incident Report Generator
                           │
                           ▼
                 Streamlit Investigation UI
```

---

# 🛠️ Tech Stack

| Category | Technology |
|------------|------------|
| Language | Python |
| Framework | Streamlit |
| AI | OpenAI GPT |
| Data Processing | Pandas |
| Threat Intelligence | AbuseIPDB |
| Visualization | Plotly |
| Testing | unittest |

---

# 📁 Project Structure

```text
ThreatLens-AI/

├── app.py
├── modules/
│   ├── parser.py
│   ├── detector.py
│   ├── attack_story.py
│   ├── analyst.py
│   ├── abuseipdb.py
│   ├── reports.py
│   └── case_manager.py
│
├── tests/
├── sample_logs/
├── assets/
├── requirements.txt
└── README.md
```

---

# ⚡ Run Locally

```bash
git clone https://github.com/25-THEBeaST-25/threatlens-ai.git

cd threatlens-ai

python3 -m venv .venv

source .venv/bin/activate

python -m pip install -r requirements.txt

python -m streamlit run app.py
```

---

# 🤖 OpenAI Integration

ThreatLens AI can generate AI-powered investigation reports.

Configure Streamlit secrets:

```toml
OPENAI_API_KEY="your-api-key"
```

---

# 🌍 AbuseIPDB Integration

Enable **Use AbuseIPDB API** from the sidebar.

Paste your API key when prompted.

If no API key is supplied, ThreatLens AI automatically falls back to local behavioral enrichment.

---

# 🧪 Running Tests

```bash
python -m unittest discover -s tests
```

---

# 📊 Example Workflow

```text
Upload Logs
      │
      ▼
Automatic Parsing
      │
      ▼
Threat Detection
      │
      ▼
Threat Intelligence
      │
      ▼
AI Investigation
      │
      ▼
Attack Story
      │
      ▼
Incident Report
      │
      ▼
Case Dashboard
```

---

# 📈 Roadmap

- [x] Multi-format log parser
- [x] Brute force detection
- [x] Credential stuffing detection
- [x] AI attack narratives
- [x] Threat intelligence enrichment
- [x] Case workflow
- [x] Analyst command suggestions
- [ ] MITRE ATT&CK mapping
- [ ] Sigma Rule generation
- [ ] Docker support
- [ ] SIEM connectors
- [ ] Real-time log monitoring

---

# 🔒 Security Notes

- Tune detection thresholds before automated blocking.
- Maintain allowlists for trusted infrastructure.
- Never upload logs containing passwords, tokens, API keys, or confidential customer data.
- Store API keys using Streamlit Secrets or your deployment platform's secret manager.

---

# 👨‍💻 Author

**Aryan Wesavkar**

Cybersecurity • AI • Backend Development

---

# 📄 License

Licensed under the MIT License.
