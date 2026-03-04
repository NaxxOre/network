try:
    from .telegram import send_telegram, telegram_enabled
except ImportError:
    from telegram import send_telegram, telegram_enabled


def _summarize_device(user_agent: str | None) -> str:
    if not user_agent:
        return "unknown"

    ua = user_agent.lower()
    if "android" in ua:
        os_name = "android"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "ios"
    elif "windows" in ua:
        os_name = "windows"
    elif "mac os x" in ua or "macintosh" in ua:
        os_name = "macos"
    elif "linux" in ua:
        os_name = "linux"
    else:
        os_name = "other"

    if "edg/" in ua:
        browser = "edge"
    elif "firefox/" in ua:
        browser = "firefox"
    elif "chrome/" in ua and "chromium" not in ua:
        browser = "chrome"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "safari"
    else:
        browser = "other"

    device_class = "mobile" if "mobile" in ua or "android" in ua or "iphone" in ua else "desktop"
    return f"{device_class}/{os_name}/{browser}"


def maybe_send_threat_alert(
    should_alert: bool,
    request_id: str,
    src_ip: str | None,
    webid: str | None,
    threat_types: list[str],
    threat_level: str,
    failed_attempts_window: int,
    parallel_sessions: int,
    resource: str,
    demo_context: dict | None = None,
) -> None:
    if not should_alert or not telegram_enabled():
        return

    run_id = (demo_context or {}).get("run_id")
    scenario = (demo_context or {}).get("scenario")
    client_label = (demo_context or {}).get("client_label")

    send_telegram(
        "WebAuthGuard security threat detected\n"
        f"request_id={request_id}\n"
        f"source_ip={src_ip}\n"
        f"webid={webid}\n"
        f"threat_types={','.join(threat_types)}\n"
        f"threat_level={threat_level}\n"
        f"failed_attempts_window={failed_attempts_window}\n"
        f"parallel_sessions={parallel_sessions}\n"
        f"scenario={scenario}\n"
        f"run_id={run_id}\n"
        f"client_label={client_label}\n"
        f"resource={resource}"
    )


def send_auth_attempt_alert(
    request_id: str,
    src_ip: str | None,
    username: str | None,
    webid: str | None,
    status: int,
    security_event: dict,
    user_agent: str | None,
    session_id: str | None,
    country_code: str | None,
    vpn_suspected: bool | None,
    demo_context: dict | None = None,
) -> None:
    if not telegram_enabled():
        return

    result = "success" if status < 400 else "failed"
    run_id = (demo_context or {}).get("run_id")
    scenario = (demo_context or {}).get("scenario")
    client_label = (demo_context or {}).get("client_label")

    send_telegram(
        "WebAuthGuard auth attempt\n"
        f"request_id={request_id}\n"
        f"result={result}\n"
        f"username={username}\n"
        f"webid={webid}\n"
        f"source_ip={src_ip}\n"
        f"status={status}\n"
        f"threat_types={','.join(security_event.get('threat_types', []))}\n"
        f"threat_level={security_event.get('threat_level')}\n"
        f"account_attempts_window={security_event.get('account_attempts_window')}\n"
        f"account_failed_attempts_window={security_event.get('account_failed_attempts_window')}\n"
        f"account_success_attempts_window={security_event.get('account_success_attempts_window')}\n"
        f"ip_account_key={security_event.get('ip_account_key')}\n"
        f"session_id={session_id}\n"
        f"country_code={country_code}\n"
        f"vpn_suspected={vpn_suspected}\n"
        f"scenario={scenario}\n"
        f"run_id={run_id}\n"
        f"client_label={client_label}\n"
        f"device={_summarize_device(user_agent)}\n"
        f"user_agent={user_agent}"
    )
