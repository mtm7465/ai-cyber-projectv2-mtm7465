from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_z(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"processed_alert_ids": []}

    try:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return {"processed_alert_ids": []}

        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"processed_alert_ids": []}

        if "processed_alert_ids" not in data or not isinstance(data["processed_alert_ids"], list):
            data["processed_alert_ids"] = []

        return data
    except (json.JSONDecodeError, OSError):
        return {"processed_alert_ids": []}


def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def get_by_path(obj: Dict[str, Any], path: str) -> Any:
    if path in obj:
        return obj[path]

    cur: Any = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def coalesce(obj: Dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = get_by_path(obj, path)
        if value not in (None, "", [], {}):
            return value
    return None


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def build_es_client() -> Elasticsearch:
    es_url = os.environ["ELASTICSEARCH_URL"]
    es_user = os.getenv("ELASTICSEARCH_USERNAME")
    es_password = os.getenv("ELASTICSEARCH_PASSWORD")
    verify_certs = os.getenv("ELASTICSEARCH_VERIFY_CERTS", "true").strip().lower() == "true"

    return Elasticsearch(
        es_url,
        basic_auth=(es_user, es_password) if es_user and es_password else None,
        verify_certs=verify_certs,
    )


def kibana_request(method: str, path: str, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    kibana_url = os.environ["KIBANA_URL"].rstrip("/")
    verify_certs = os.getenv("KIBANA_VERIFY_CERTS", "true").strip().lower() == "true"

    response = requests.request(
        method=method,
        url=f"{kibana_url}{path}",
        auth=(os.environ["KIBANA_USERNAME"], os.environ["KIBANA_PASSWORD"]),
        headers={
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        },
        json=json_body,
        verify=verify_certs,
        timeout=300,
    )

    if not response.ok:
        raise RuntimeError(f"{response.status_code} {response.text}")

    if response.text.strip():
        return response.json()
    return {}


def fetch_unprocessed_open_alerts(
    es: Elasticsearch,
    index_pattern: str,
    processed_ids: set[str],
    batch_size: int,
    target_count: int,
) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    offset = 0
    unlimited = target_count == 0

    while True:
        query = {
            "size": batch_size,
            "from": offset,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"kibana.alert.workflow_status": "open"}}
                    ]
                }
            },
        }

        response = es.search(index=index_pattern, body=query)
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            break

        new_in_page = 0
        for hit in hits:
            alert_id = hit.get("_id")
            if alert_id and alert_id not in processed_ids:
                collected.append(hit)
                new_in_page += 1
                if not unlimited and len(collected) >= target_count:
                    return collected

        offset += batch_size

        # stop if page returned only already-processed items and there are no more pages later
        if len(hits) < batch_size:
            break

    return collected


def extract_mitre_ids(alert_source: Dict[str, Any]) -> List[str]:
    mitre_ids: List[str] = []

    threat_items = coalesce(
        alert_source,
        "kibana.alert.rule.threat",
        "kibana.alert.rule.parameters.threat",
    )

    for item in ensure_list(threat_items):
        if not isinstance(item, dict):
            continue

        tactic = item.get("tactic")
        if isinstance(tactic, dict):
            tactic_id = tactic.get("id")
            if tactic_id:
                mitre_ids.append(str(tactic_id))

        for technique in ensure_list(item.get("technique")):
            if not isinstance(technique, dict):
                continue

            technique_id = technique.get("id")
            if technique_id:
                mitre_ids.append(str(technique_id))

            for subtechnique in ensure_list(technique.get("subtechnique")):
                if isinstance(subtechnique, dict) and subtechnique.get("id"):
                    mitre_ids.append(str(subtechnique["id"]))

    seen = set()
    ordered = []
    for item in mitre_ids:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def normalize_alert(hit: Dict[str, Any]) -> Dict[str, Any]:
    source = hit.get("_source", {})

    return {
        "alert": {
            "id": hit.get("_id"),
            "index": hit.get("_index"),
            "case_attach_index": os.getenv("ALERT_INDEX_PATTERN", ".alerts-security.alerts-default"),
            "timestamp": source.get("@timestamp"),
            "rule_id": coalesce(source, "kibana.alert.rule.rule_id", "kibana.alert.rule.uuid"),
            "rule_name": coalesce(source, "kibana.alert.rule.name"),
            "rule_description": coalesce(
                source,
                "kibana.alert.rule.description",
                "kibana.alert.rule.parameters.description",
            ),
            "reason": coalesce(source, "kibana.alert.reason", "message"),
            "severity": coalesce(source, "kibana.alert.severity", "kibana.alert.rule.severity"),
            "risk_score": coalesce(source, "kibana.alert.risk_score", "kibana.alert.rule.risk_score"),
            "workflow_status": coalesce(source, "kibana.alert.workflow_status"),
            "alert_status": coalesce(source, "kibana.alert.status"),
            "host": coalesce(source, "host.name"),
            "user": coalesce(source, "user.name"),
            "process_name": coalesce(source, "process.name"),
            "process_command_line": coalesce(source, "process.command_line"),
            "parent_process_name": coalesce(source, "process.parent.name"),
            "parent_process_command_line": coalesce(source, "process.parent.command_line"),
            "dataset": coalesce(source, "event.dataset", "data_stream.dataset"),
            "event_category": ensure_list(coalesce(source, "event.category")),
            "event_type": ensure_list(coalesce(source, "event.type")),
            "original_event_code": coalesce(source, "kibana.alert.original_event.code", "event.code"),
            "original_event_action": coalesce(source, "kibana.alert.original_event.action", "event.action"),
            "mitre_from_rule": extract_mitre_ids(source),
        }
    }


def render_prompt(template: str, alert_case: Dict[str, Any]) -> str:
    return template.replace("{{ALERT_CASE_JSON}}", json.dumps(alert_case, indent=2, ensure_ascii=False))


def call_ollama(prompt: str) -> Dict[str, Any]:
    payload = {
        "model": os.environ["OLLAMA_MODEL"],
        "prompt": prompt,
        "stream": False,
        "format": {
            "type": "object",
            "properties": {
                "triage_decision": {
                    "type": "string",
                    "enum": ["benign", "suspicious", "malicious"],
                },
                "priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "reasoning_summary": {"type": "string"},
                "recommended_action": {
                    "type": "string",
                    "enum": ["ignore", "investigate", "contain", "escalate"],
                },
                "mitre_attack": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "analyst_questions": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": [
                "triage_decision",
                "priority",
                "reasoning_summary",
                "recommended_action",
                "mitre_attack",
                "analyst_questions",
            ],
        },
        "options": {
            "temperature": 0.2,
        },
    }

    response = requests.post(
        os.environ["OLLAMA_URL"],
        json=payload,
        timeout=300,
    )
    response.raise_for_status()

    data = response.json()
    raw_text = data.get("response", "").strip()
    return json.loads(raw_text)


def create_case(alert_case: Dict[str, Any]) -> Dict[str, Any]:
    a = alert_case["alert"]
    title = f"AI Triage - {a['rule_name']} - {a['host']} - {a['id'][:8]}"
    description = (
        "Automatically created by the AI triage agent.\n\n"
        f"Rule: {a['rule_name']}\n"
        f"Host: {a['host']}\n"
        f"User: {a['user']}\n"
        f"Severity: {a['severity']}\n"
        f"Reason: {a['reason']}\n"
    )

    body = {
        "title": title,
        "description": description,
        "severity": (a["severity"] or "low").lower(),
        "tags": ["ai-triage", "auto-created"],
        "owner": "securitySolution",
        "connector": {
            "id": "none",
            "name": "none",
            "type": ".none",
            "fields": None,
        },
        "settings": {
            "syncAlerts": True,
        },
    }

    return kibana_request("POST", "/api/cases", body)


def attach_alert_to_case(case_id: str, alert_case: Dict[str, Any]) -> Dict[str, Any]:
    a = alert_case["alert"]

    body = {
        "type": "alert",
        "alertId": a["id"],
        "index": a["case_attach_index"],
        "owner": "securitySolution",
        "rule": {
            "id": a.get("rule_id"),
            "name": a.get("rule_name"),
        },
    }

    return kibana_request("POST", f"/api/cases/{case_id}/comments", body)


def format_llm_comment(llm_triage: Dict[str, Any]) -> str:
    mitre = ", ".join(llm_triage.get("mitre_attack", [])) or "None"
    questions = llm_triage.get("analyst_questions", [])
    question_text = "\n".join(f"- {q}" for q in questions) if questions else "- None"

    return (
        "AI Triage Summary\n"
        f"Decision: {llm_triage.get('triage_decision')}\n"
        f"Priority: {llm_triage.get('priority')}\n"
        f"Recommended action: {llm_triage.get('recommended_action')}\n\n"
        f"Reasoning:\n{llm_triage.get('reasoning_summary')}\n\n"
        f"Suggested ATT&CK:\n{mitre}\n\n"
        f"Analyst questions:\n{question_text}\n"
    )


def add_comment_to_case(case_id: str, llm_triage: Dict[str, Any]) -> Dict[str, Any]:
    body = {
        "type": "user",
        "comment": format_llm_comment(llm_triage),
        "owner": "securitySolution",
    }
    return kibana_request("POST", f"/api/cases/{case_id}/comments", body)


def main() -> None:
    load_dotenv()

    alert_index_pattern = os.getenv("ALERT_INDEX_PATTERN", ".alerts-security.alerts-default")
    batch_size = int(os.getenv("FETCH_BATCH_SIZE", "25"))
    max_new_alerts = int(os.getenv("MAX_NEW_ALERTS_PER_RUN", "0"))
    poll_interval_seconds = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))

    state_path = Path("state/processed_alerts.json")
    output_path = Path("output/triage_results_v2.jsonl")
    prompt_path = Path("prompts/triage_alert_prompt.txt")

    prompt_template = prompt_path.read_text(encoding="utf-8")
    es = build_es_client()

    print("Starting Version 2 triage agent. Press Ctrl+C to stop.")

    while True:
        state = load_state(state_path)
        processed_ids = set(state.get("processed_alert_ids", []))

        hits = fetch_unprocessed_open_alerts(
            es=es,
            index_pattern=alert_index_pattern,
            processed_ids=processed_ids,
            batch_size=batch_size,
            target_count=max_new_alerts,
        )

        print(f"Found {len(hits)} unprocessed open alerts.")

        new_count = 0
        error_count = 0

        for hit in hits:
            alert_id = hit.get("_id")
            if not alert_id:
                continue

            try:
                alert_case = normalize_alert(hit)
                prompt = render_prompt(prompt_template, alert_case)
                llm_triage = call_ollama(prompt)

                case_resp = create_case(alert_case)
                case_id = case_resp.get("id")
                if not case_id:
                    raise RuntimeError("Case creation succeeded but no case ID was returned.")

                attach_resp = attach_alert_to_case(
                    case_id=case_id,
                    alert_case=alert_case,
                )

                comment_resp = add_comment_to_case(case_id=case_id, llm_triage=llm_triage)

                triage_mttr_seconds = None
                if alert_case["alert"]["timestamp"] and comment_resp.get("created_at"):
                    triage_mttr_seconds = (
                        parse_iso_z(comment_resp["created_at"]) - parse_iso_z(alert_case["alert"]["timestamp"])
                    ).total_seconds()

                result_row = {
                    "alert_id": alert_case["alert"]["id"],
                    "alert_index": alert_case["alert"]["index"],
                    "alert_timestamp": alert_case["alert"]["timestamp"],
                    "host": alert_case["alert"]["host"],
                    "rule_name": alert_case["alert"]["rule_name"],
                    "alert_case": alert_case,
                    "llm_triage": llm_triage,
                    "case_id": case_id,
                    "case_created_at": case_resp.get("created_at"),
                    "comment_created_at": comment_resp.get("created_at"),
                    "triage_mttr_seconds": triage_mttr_seconds,
                }

                append_jsonl(output_path, result_row)

                processed_ids.add(alert_id)
                new_count += 1

                state["processed_alert_ids"] = sorted(processed_ids)
                save_state(state_path, state)

                print(
                    f"[OK] {alert_case['alert']['rule_name']} | "
                    f"{alert_case['alert']['host']} | "
                    f"{alert_case['alert']['severity']} | "
                    f"case={case_id}"
                )

            except Exception as exc:
                error_count += 1
                print(f"[ERROR] alert_id={alert_id}: {exc}")

        state["processed_alert_ids"] = sorted(processed_ids)
        save_state(state_path, state)

        print("-" * 80)
        print(f"New triaged alerts this cycle: {new_count}")
        print(f"Errors this cycle:            {error_count}")
        print(f"Results written to:           {output_path}")
        print(f"Sleeping for {poll_interval_seconds} seconds...\n")

        time.sleep(poll_interval_seconds)


if __name__ == "__main__":
    main()
