# ThreatLens AI

ThreatLens AI is a Streamlit cybersecurity investigation assistant. It parses SSH/syslog, nginx/apache-style access logs, ISO timestamp text logs, and line-delimited JSON events, then turns detections into an attack story, analyst commands, reports, and a lightweight case workflow.

## What Makes It Different

- **Attack Story Mode:** converts scattered events into a readable investigation narrative.
- **SOC command helper:** suggests grep, journalctl, and login-history commands for the suspicious IPs.
- **Case workflow:** tracks owner, status, notes, highest risk, and downloadable case files.
- **Threat intel layer:** enriches alerts with local behavioral tags and optional AbuseIPDB lookups.
- **False positive controls:** allowlist known IPs, internal networks, and trusted user agents.

## Detection Coverage

- Brute force authentication attempts
- Credential stuffing across many usernames
- Successful login after repeated failures
- Suspicious endpoint probing for admin/config/traversal paths
- Scanner-like user-agent and endpoint-spread hints

## Run Locally

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Optional Integrations

### OpenAI Analyst Report

Add your OpenAI key to Streamlit secrets:

```toml
OPENAI_API_KEY = "your-key"
```

### AbuseIPDB Enrichment

Enable **Use AbuseIPDB API** in the sidebar and paste your AbuseIPDB key. If no key is provided, ThreatLens still performs local enrichment without network calls.

## Test

```bash
python -m unittest discover -s tests
```

## Production Notes

- Tune thresholds before using results for automated blocking.
- Keep internal ranges, scanner IPs, uptime bots, and monitoring user agents in allowlists.
- Do not upload logs containing passwords, tokens, API keys, or private customer data.
- Store API keys in Streamlit secrets or your hosting provider's secret manager.

