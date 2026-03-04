try:
    from .oslog import OSLogger
except ImportError:
    from oslog import OSLogger


def build_security_event(threat, event_type: str) -> dict:
    return {
        "event_type": event_type,
        "login_result": threat.login_result,
        "success_ip": threat.success_ip,
        "failed_ip": threat.failed_ip,
        "possible_threat": threat.possible_threat,
        "threat_types": threat.threat_types,
        "threat_level": threat.threat_level,
        "threat_score": threat.threat_score,
        "failed_attempts_window": threat.failed_attempts_window,
        "window_seconds": threat.window_seconds,
        "different_ip_login": threat.different_ip_login,
        "distinct_ips_window": threat.distinct_ips_window,
        "vpn_geography_anomaly": threat.vpn_geography_anomaly,
        "vpn_suspected": threat.vpn_suspected,
        "country_code": threat.country_code,
        "distinct_countries_window": threat.distinct_countries_window,
        "parallel_sessions": threat.parallel_sessions,
        "parallel_session_violation": threat.parallel_session_violation,
        "policy_max_parallel_sessions": threat.policy_max_parallel_sessions,
        "session_id": threat.session_id,
        "source_key": threat.source_key,
        "attempted_account": threat.attempted_account,
        "ip_account_key": threat.ip_account_key,
        "auth_attempt_window_seconds": threat.auth_attempt_window_seconds,
        "account_attempts_window": threat.account_attempts_window,
        "account_failed_attempts_window": threat.account_failed_attempts_window,
        "account_success_attempts_window": threat.account_success_attempts_window,
        "account_failed_attempts_all_window": threat.account_failed_attempts_all_window,
        "distinct_failed_accounts_window": threat.distinct_failed_accounts_window,
        "distinct_failed_sources_window": threat.distinct_failed_sources_window,
        "account_brute_force": threat.account_brute_force,
        "credential_stuffing": threat.credential_stuffing,
        "distributed_account_attack": threat.distributed_account_attack,
    }


def emit_auth_event(
    logger: OSLogger,
    request_id: str,
    src_ip: str | None,
    path: str,
    status: int,
    username: str | None,
    webid: str | None,
    security_event: dict,
    demo_context: dict | None = None,
) -> None:
    demo = {
        "run_id": (demo_context or {}).get("run_id"),
        "scenario": (demo_context or {}).get("scenario"),
        "client_label": (demo_context or {}).get("client_label"),
    }
    event = {
        "request_id": request_id,
        "src_ip": src_ip,
        "http": {"method": "POST", "path": path, "status": status},
        "agent": {"webid": webid, "authn": "auth-form", "username": username},
        "origin": None,
        "demo": demo,
        "security": security_event,
        "wac": {
            "resource": path,
            "required_mode": "auth",
            "decision": "allow" if status < 400 else "deny",
            "reason": "auth_success" if status < 400 else "auth_failed",
            "matched_authz": None,
        },
    }
    logger.emit(event)
