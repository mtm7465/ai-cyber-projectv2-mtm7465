# GenAI SOC Triage Agent (Course Project)

This repository contains a course project for **Generative AI in Cybersecurity (CSEC 559/659, RIT)**. The agent continuously triages open Elastic Security alerts by combining Elasticsearch/Kibana APIs with a local Ollama model (`qwen2.5:3b`).

## Project Overview

The script:
1. Queries **open** Elastic Security alerts from Elasticsearch.
2. Normalizes alert context into a compact JSON payload.
3. Sends the payload to a local Ollama model for triage.
4. Creates an Elastic Case for the alert.
5. Attaches the alert and posts an AI-generated triage comment.
6. Records processed alert IDs and JSONL output for traceability.

## Architecture / Workflow Summary

- **Polling loop** (`run_alert_case_triage.py`): checks for unprocessed, open alerts.
- **Normalization layer**: extracts alert/rule/host/user/process/ATT&CK-relevant fields.
- **LLM step**: renders prompt template and calls Ollama `generate` API (JSON output).
- **Case actions** (Kibana Cases API):
  - Create case
  - Attach alert to case
  - Add AI triage comment
- **Persistence**:
  - `state/processed_alerts.json` prevents reprocessing.
  - `output/triage_results_v2.jsonl` stores per-alert outcomes.

## Requirements

- Python 3.10+
- Access to:
  - Elasticsearch (alerts index)
  - Kibana Cases API
  - Local/accessible Ollama instance with `qwen2.5:3b`
- Python packages from `requirements.txt`

## Installation

```bash
# 1) Clone and enter repository
git clone <your-repo-url>
cd ai-cyber-projectv2-mtm7465

# 2) Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3) Install dependencies
pip install -r requirements.txt

# 4) Configure environment
cp .env.example .env
# then edit .env with your local values
```

## Environment Variables (`.env.example`)

Use `.env.example` as the template for `.env`.

- `ELASTICSEARCH_URL`: Elasticsearch endpoint.
- `ELASTICSEARCH_USERNAME` / `ELASTICSEARCH_PASSWORD`: Elasticsearch credentials.
- `ELASTICSEARCH_VERIFY_CERTS`: `true` or `false` TLS verification.
- `KIBANA_URL`: Kibana base URL.
- `KIBANA_USERNAME` / `KIBANA_PASSWORD`: Kibana credentials.
- `KIBANA_VERIFY_CERTS`: `true` or `false` TLS verification.
- `ALERT_INDEX_PATTERN`: alert index pattern (default Elastic Security alerts index).
- `MAX_NEW_ALERTS_PER_RUN`: max new alerts per cycle (`0` means unlimited).
- `FETCH_BATCH_SIZE`: search page size for alert retrieval.
- `POLL_INTERVAL_SECONDS`: sleep interval between polling cycles.
- `OLLAMA_URL`: Ollama generate endpoint.
- `OLLAMA_MODEL`: model name (expected: `qwen2.5:3b`).

## How to Run the Agent

```bash
python run_alert_case_triage.py
```

The agent runs continuously until interrupted (Ctrl+C). Each cycle logs summary stats and writes outputs to disk.

## Expected Folder Structure

```text
.
├── .env.example
├── requirements.txt
├── run_alert_case_triage.py
├── prompts/
│   └── triage_alert_prompt.txt
├── state/
│   └── processed_alerts.json      # created at runtime
└── output/
    └── triage_results_v2.jsonl    # created/appended at runtime
```

## Notes on `state/` and `output/`

- `state/processed_alerts.json` tracks processed alert IDs so alerts are not triaged repeatedly across cycles.
- `output/triage_results_v2.jsonl` appends one JSON record per successfully triaged alert (includes alert snapshot, model output, case metadata, and timing fields).
- Deleting `state/processed_alerts.json` resets deduplication behavior.

## Safety / Privacy

- Do **not** commit `.env`, credentials, or real infrastructure values.
- Do **not** commit local runtime artifacts unless intentionally sanitized (`state/`, `output/`, debug logs).
- Review AI-generated triage comments before operational response in production SOC workflows.

## Course / Academic Attribution

Developed as an academic project for **RIT Generative AI in Cybersecurity (CSEC 559/659)**, by **Minn**, **Jonah**, and **Rhythm**.
