from __future__ import annotations

from collections import Counter
from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_window_minutes(value: int | None) -> int:
    if value is None:
        return 15
    return max(1, min(240, int(value)))


def _severity(max_threat_score: int, threat_events: int) -> str:
    if max_threat_score >= 70 or threat_events >= 10:
        return "high"
    if max_threat_score >= 40 or threat_events >= 4:
        return "medium"
    if threat_events > 0:
        return "low"
    return "none"


def _recommended_actions(threat_type_counter: Counter[str]) -> list[str]:
    actions: list[str] = []

    if threat_type_counter.get("brute_force", 0) > 0 or threat_type_counter.get("account_brute_force", 0) > 0:
        actions.append("Enable temporary lockout or CAPTCHA for repeated failed authentication.")
    if threat_type_counter.get("credential_stuffing", 0) > 0:
        actions.append("Rate-limit login attempts per source and challenge suspicious account enumeration.")
    if threat_type_counter.get("distributed_account_attack", 0) > 0:
        actions.append("Block or challenge sources with many session IDs targeting the same account.")
    if threat_type_counter.get("parallel_session_policy_violation", 0) > 0:
        actions.append("Invalidate excess active sessions and enforce stricter session concurrency limits.")
    if threat_type_counter.get("vpn_geography_anomaly", 0) > 0 or threat_type_counter.get("vpn_proxy_network", 0) > 0:
        actions.append("Require step-up verification for geography/VPN anomalies.")

    if not actions:
        actions.append("Continue monitoring; no elevated threat pattern observed in selected window.")

    return actions


def _summary_text(
    window_minutes: int,
    run_id: str | None,
    threat_events: int,
    total_events: int,
    severity: str,
    top_threat_types: list[dict[str, Any]],
    top_source_ips: list[dict[str, Any]],
    top_accounts: list[dict[str, Any]],
) -> str:
    run_part = f" for run_id={run_id}" if run_id else ""
    threat_part = ", ".join(item["value"] for item in top_threat_types[:3]) or "none"
    src_part = ", ".join(item["value"] for item in top_source_ips[:2]) or "none"
    acct_part = ", ".join(item["value"] for item in top_accounts[:2]) or "none"

    return (
        f"In the last {window_minutes} minutes{run_part}, "
        f"{threat_events} of {total_events} events were threat-related "
        f"(severity={severity}). Top threat patterns: {threat_part}. "
        f"Most active sources: {src_part}. Most targeted accounts: {acct_part}."
    )


def summarize_incidents_from_hits(
    hits: list[dict[str, Any]],
    window_minutes: int = 15,
    run_id: str | None = None,
) -> dict[str, Any]:
    window = _normalize_window_minutes(window_minutes)

    source_ip_counter: Counter[str] = Counter()
    account_counter: Counter[str] = Counter()
    threat_type_counter: Counter[str] = Counter()
    max_threat_score = 0
    threat_events = 0

    for hit in hits:
        source = hit.get("_source") or {}
        security = source.get("security") or {}
        agent = source.get("agent") or {}

        src_ip = source.get("src_ip")
        if src_ip:
            source_ip_counter[str(src_ip)] += 1

        username = agent.get("username") or security.get("attempted_account")
        if username:
            account_counter[str(username).lower()] += 1

        threat_score = _safe_int(security.get("threat_score"), 0)
        if threat_score > max_threat_score:
            max_threat_score = threat_score

        threat_types = security.get("threat_types") or []
        if not isinstance(threat_types, list):
            threat_types = [str(threat_types)]
        for threat_type in threat_types:
            if threat_type:
                threat_type_counter[str(threat_type)] += 1

        possible = bool(security.get("possible_threat"))
        if possible or threat_types or threat_score > 0:
            threat_events += 1

    total_events = len(hits)
    severity = _severity(max_threat_score=max_threat_score, threat_events=threat_events)

    top_source_ips = [{"value": ip, "count": count} for ip, count in source_ip_counter.most_common(5)]
    top_accounts = [{"value": account, "count": count} for account, count in account_counter.most_common(5)]
    top_threat_types = [{"value": threat, "count": count} for threat, count in threat_type_counter.most_common(5)]
    recommended_actions = _recommended_actions(threat_type_counter)

    return {
        "window_minutes": window,
        "run_id": run_id,
        "total_events": total_events,
        "threat_events": threat_events,
        "top_source_ips": top_source_ips,
        "top_accounts": top_accounts,
        "top_threat_types": top_threat_types,
        "max_threat_score": max_threat_score,
        "severity": severity,
        "summary_text": _summary_text(
            window_minutes=window,
            run_id=run_id,
            threat_events=threat_events,
            total_events=total_events,
            severity=severity,
            top_threat_types=top_threat_types,
            top_source_ips=top_source_ips,
            top_accounts=top_accounts,
        ),
        "recommended_actions": recommended_actions,
    }


def fetch_incident_summary(
    opensearch_client,
    window_minutes: int = 15,
    run_id: str | None = None,
) -> dict[str, Any]:
    window = _normalize_window_minutes(window_minutes)
    filters: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{window}m", "lte": "now"}}},
    ]

    if run_id:
        filters.append({"term": {"demo.run_id.keyword": run_id}})

    query = {
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "src_ip",
            "agent.username",
            "security.possible_threat",
            "security.threat_score",
            "security.threat_types",
            "security.attempted_account",
            "demo.run_id",
        ],
        "query": {"bool": {"filter": filters}},
    }

    response = opensearch_client.search(index="webauthguard-events-*", body=query)
    hits = (response.get("hits") or {}).get("hits") or []
    return summarize_incidents_from_hits(hits=hits, window_minutes=window, run_id=run_id)
