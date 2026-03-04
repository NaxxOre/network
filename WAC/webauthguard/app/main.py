import os
import uuid
import httpx
from fastapi import FastAPI, Form, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

try:
    from .wac import Decision, method_to_mode, allowed_by_acl
    from .oslog import OSLogger
    from .telegram import telegram_enabled, send_telegram
    from .threat import SecurityRiskEngine
    from .ip_intel import IPIntelResolver
    from .auth import AuthStore
    from .alerts import maybe_send_threat_alert, send_auth_attempt_alert
    from .auth_ui import auth_page, get_authenticated_user, set_auth_cookie
    from .event_builders import build_security_event, emit_auth_event
    from .incident_summary import fetch_incident_summary
    from .request_utils import (
        extract_acl_link,
        fetch_acl_for,
        normalize_country_code,
        normalize_public_ip,
        resolve_source_ip,
        resource_url_for,
    )
except ImportError:
    from wac import Decision, method_to_mode, allowed_by_acl
    from oslog import OSLogger
    from telegram import telegram_enabled, send_telegram
    from threat import SecurityRiskEngine
    from ip_intel import IPIntelResolver
    from auth import AuthStore
    from alerts import maybe_send_threat_alert, send_auth_attempt_alert
    from auth_ui import auth_page, get_authenticated_user, set_auth_cookie
    from event_builders import build_security_event, emit_auth_event
    from incident_summary import fetch_incident_summary
    from request_utils import (
        extract_acl_link,
        fetch_acl_for,
        normalize_country_code,
        normalize_public_ip,
        resolve_source_ip,
        resource_url_for,
    )

app = FastAPI()
logger = OSLogger()
detector = SecurityRiskEngine()
ip_intel = IPIntelResolver()
auth = AuthStore()

RESOURCE_BASE = os.environ.get("RESOURCE_BASE", "http://resource:8001")
AUTH_COOKIE_NAME = "wac_access_token"
AUTH_COOKIE_SECURE = os.environ.get("AUTH_COOKIE_SECURE", "false").lower() == "true"
SESSION_COOKIE_NAME = "wac_session_id"
SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 30


def ensure_session_cookie(request: Request, response: Response) -> str:
    existing = (request.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    session_id = existing or str(uuid.uuid4())
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=False,
        samesite="lax",
        secure=AUTH_COOKIE_SECURE,
        max_age=SESSION_COOKIE_MAX_AGE,
    )
    return session_id


def resolve_session_id(request: Request, submitted_session_id: str | None) -> str | None:
    if submitted_session_id and submitted_session_id.strip():
        return submitted_session_id.strip()

    header_session_id = request.headers.get("X-Session-ID")
    if header_session_id and header_session_id.strip():
        return header_session_id.strip()

    cookie_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_session_id and cookie_session_id.strip():
        return cookie_session_id.strip()

    return None


def _clean_demo_value(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    return cleaned or None


def resolve_demo_context(request: Request) -> dict[str, str | None]:
    return {
        "run_id": _clean_demo_value(request.headers.get("X-Demo-Run-ID")),
        "scenario": _clean_demo_value(request.headers.get("X-Demo-Scenario")),
        "client_label": _clean_demo_value(request.headers.get("X-Client-Label")),
    }


async def resolve_network_signals(
    request: Request,
    country_code_hint: str | None = None,
    public_ip_hint: str | None = None,
    vpn_suspected_hint: str | None = None,
) -> tuple[str | None, str | None, bool]:
    source_ip = resolve_source_ip(request)
    header_country_code = normalize_country_code(request.headers.get("X-Country") or request.headers.get("CF-IPCountry"))
    hinted_country_code = normalize_country_code(country_code_hint)
    hinted_public_ip = normalize_public_ip(public_ip_hint or request.headers.get("X-Client-Public-IP"))
    vpn_header = (request.headers.get("X-VPN-Suspected") or "").strip().lower()
    vpn_hint = vpn_header in {"1", "true", "yes"}
    vpn_form_hint = (vpn_suspected_hint or "").strip().lower() in {"1", "true", "yes"}

    lookup_ip = hinted_public_ip or source_ip
    intel = await ip_intel.lookup(lookup_ip)
    country_code = header_country_code or hinted_country_code or intel.country_code
    return source_ip, country_code, (vpn_form_hint or vpn_hint or intel.vpn_suspected)


@app.get("/net-intel")
async def net_intel(request: Request):
    source_ip = resolve_source_ip(request)
    intel = await ip_intel.lookup(source_ip)
    vpn_header = (request.headers.get("X-VPN-Suspected") or "").strip().lower()
    vpn_hint = vpn_header in {"1", "true", "yes"}
    return {
        "source_ip": source_ip,
        "public_ip": intel.ip,
        "country_code": intel.country_code,
        "vpn_suspected": (vpn_hint or intel.vpn_suspected),
    }


@app.get("/incidents/summary")
async def incidents_summary(
    minutes: int = Query(default=15, ge=1, le=240),
    run_id: str | None = Query(default=None),
):
    try:
        return fetch_incident_summary(
            opensearch_client=logger.client,
            window_minutes=minutes,
            run_id=run_id,
        )
    except Exception as exc:
        return JSONResponse(
            {"error": "incident_summary_unavailable", "detail": str(exc)},
            status_code=503,
        )


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https://ipwho.is https://api.ipify.org; "
        "base-uri 'self'; form-action 'self'"
    )
    return response


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    user = get_authenticated_user(request, auth, AUTH_COOKIE_NAME)
    if user:
        response = HTMLResponse(
            f"<h2>Signed in as {user.username}</h2><p>WebID: {user.webid}</p>"
            "<p><a href='/docs'>API docs</a></p>"
            "<form method='post' action='/logout'><button type='submit'>Logout</button></form>"
        )
        ensure_session_cookie(request, response)
        return response
    response = RedirectResponse(url="/login", status_code=302)
    ensure_session_cookie(request, response)
    return response


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request, msg: str = ""):
    response = HTMLResponse(auth_page("Sign Up", "Create account", "/signup", "Sign Up", msg))
    ensure_session_cookie(request, response)
    return response


@app.post("/signup")
async def signup_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    session_id: str | None = Form(None),
    country_code_form: str | None = Form(None),
    public_ip: str | None = Form(None),
    vpn_suspected_form: str | None = Form(None),
):
    request_id = str(uuid.uuid4())
    demo_context = resolve_demo_context(request)
    src_ip, country_code, vpn_suspected = await resolve_network_signals(
        request,
        country_code_hint=country_code_form,
        public_ip_hint=public_ip,
        vpn_suspected_hint=vpn_suspected_form,
    )
    session_id = resolve_session_id(request, session_id)

    if password != confirm_password:
        threat, should_alert = detector.assess(
            src_ip=src_ip,
            allowed=False,
            webid=None,
            session_id=session_id,
            country_code=country_code,
            vpn_suspected=vpn_suspected,
            attempted_account=username,
            event_type="auth_signup",
        )
        security_event = build_security_event(threat, event_type="auth_signup")
        emit_auth_event(
            logger=logger,
            request_id=request_id,
            src_ip=src_ip,
            path="/signup",
            status=400,
            username=username,
            webid=None,
            security_event=security_event,
            demo_context=demo_context,
        )
        maybe_send_threat_alert(
            should_alert=should_alert,
            request_id=request_id,
            src_ip=src_ip,
            webid=None,
            threat_types=threat.threat_types,
            threat_level=threat.threat_level,
            failed_attempts_window=threat.failed_attempts_window,
            parallel_sessions=threat.parallel_sessions,
            resource="/signup",
            demo_context=demo_context,
        )
        response = HTMLResponse(
            auth_page("Sign Up", "Create account", "/signup", "Sign Up", "Passwords do not match"),
            status_code=400,
        )
        ensure_session_cookie(request, response)
        return response

    try:
        user = auth.create_user(username=username, email=email, password=password)
    except ValueError as exc:
        threat, should_alert = detector.assess(
            src_ip=src_ip,
            allowed=False,
            webid=None,
            session_id=session_id,
            country_code=country_code,
            vpn_suspected=vpn_suspected,
            attempted_account=username,
            event_type="auth_signup",
        )
        security_event = build_security_event(threat, event_type="auth_signup")
        emit_auth_event(
            logger=logger,
            request_id=request_id,
            src_ip=src_ip,
            path="/signup",
            status=400,
            username=username,
            webid=None,
            security_event=security_event,
            demo_context=demo_context,
        )
        maybe_send_threat_alert(
            should_alert=should_alert,
            request_id=request_id,
            src_ip=src_ip,
            webid=None,
            threat_types=threat.threat_types,
            threat_level=threat.threat_level,
            failed_attempts_window=threat.failed_attempts_window,
            parallel_sessions=threat.parallel_sessions,
            resource="/signup",
            demo_context=demo_context,
        )
        response = HTMLResponse(auth_page("Sign Up", "Create account", "/signup", "Sign Up", str(exc)), status_code=400)
        ensure_session_cookie(request, response)
        return response

    token = auth.issue_token(user)
    threat, should_alert = detector.assess(
        src_ip=src_ip,
        allowed=True,
        webid=user.webid,
        session_id=session_id,
        country_code=country_code,
        vpn_suspected=vpn_suspected,
        attempted_account=user.username,
        event_type="auth_signup",
    )
    security_event = build_security_event(threat, event_type="auth_signup")
    emit_auth_event(
        logger=logger,
        request_id=request_id,
        src_ip=src_ip,
        path="/signup",
        status=200,
        username=user.username,
        webid=user.webid,
        security_event=security_event,
        demo_context=demo_context,
    )
    maybe_send_threat_alert(
        should_alert=should_alert,
        request_id=request_id,
        src_ip=src_ip,
        webid=user.webid,
        threat_types=threat.threat_types,
        threat_level=threat.threat_level,
        failed_attempts_window=threat.failed_attempts_window,
        parallel_sessions=threat.parallel_sessions,
        resource="/signup",
        demo_context=demo_context,
    )
    resp = RedirectResponse(url="/", status_code=303)
    set_auth_cookie(resp, token, AUTH_COOKIE_NAME, AUTH_COOKIE_SECURE)
    ensure_session_cookie(request, resp)
    return resp


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, msg: str = ""):
    response = HTMLResponse(auth_page("Login", "Sign in", "/login", "Login", msg))
    ensure_session_cookie(request, response)
    return response


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session_id: str | None = Form(None),
    country_code_form: str | None = Form(None),
    public_ip: str | None = Form(None),
    vpn_suspected_form: str | None = Form(None),
):
    request_id = str(uuid.uuid4())
    demo_context = resolve_demo_context(request)
    src_ip, country_code, vpn_suspected = await resolve_network_signals(
        request,
        country_code_hint=country_code_form,
        public_ip_hint=public_ip,
        vpn_suspected_hint=vpn_suspected_form,
    )
    session_id = resolve_session_id(request, session_id)
    user_agent = request.headers.get("User-Agent")

    user = auth.authenticate(username=username, password=password)
    if not user:
        threat, should_alert = detector.assess(
            src_ip=src_ip,
            allowed=False,
            webid=None,
            session_id=session_id,
            country_code=country_code,
            vpn_suspected=vpn_suspected,
            attempted_account=username,
            event_type="auth_login",
        )
        security_event = build_security_event(threat, event_type="auth_login")
        emit_auth_event(
            logger=logger,
            request_id=request_id,
            src_ip=src_ip,
            path="/login",
            status=401,
            username=username,
            webid=None,
            security_event=security_event,
            demo_context=demo_context,
        )
        send_auth_attempt_alert(
            request_id=request_id,
            src_ip=src_ip,
            username=username,
            webid=None,
            status=401,
            security_event=security_event,
            user_agent=user_agent,
            session_id=session_id,
            country_code=country_code,
            vpn_suspected=vpn_suspected,
            demo_context=demo_context,
        )
        maybe_send_threat_alert(
            should_alert=should_alert,
            request_id=request_id,
            src_ip=src_ip,
            webid=None,
            threat_types=threat.threat_types,
            threat_level=threat.threat_level,
            failed_attempts_window=threat.failed_attempts_window,
            parallel_sessions=threat.parallel_sessions,
            resource="/login",
            demo_context=demo_context,
        )
        response = HTMLResponse(
            auth_page("Login", "Sign in", "/login", "Login", "Invalid username or password"),
            status_code=401,
        )
        ensure_session_cookie(request, response)
        return response

    token = auth.issue_token(user)
    threat, should_alert = detector.assess(
        src_ip=src_ip,
        allowed=True,
        webid=user.webid,
        session_id=session_id,
        country_code=country_code,
        vpn_suspected=vpn_suspected,
        attempted_account=user.username,
        event_type="auth_login",
    )
    security_event = build_security_event(threat, event_type="auth_login")
    emit_auth_event(
        logger=logger,
        request_id=request_id,
        src_ip=src_ip,
        path="/login",
        status=200,
        username=user.username,
        webid=user.webid,
        security_event=security_event,
        demo_context=demo_context,
    )
    send_auth_attempt_alert(
        request_id=request_id,
        src_ip=src_ip,
        username=user.username,
        webid=user.webid,
        status=200,
        security_event=security_event,
        user_agent=user_agent,
        session_id=session_id,
        country_code=country_code,
        vpn_suspected=vpn_suspected,
        demo_context=demo_context,
    )
    maybe_send_threat_alert(
        should_alert=should_alert,
        request_id=request_id,
        src_ip=src_ip,
        webid=user.webid,
        threat_types=threat.threat_types,
        threat_level=threat.threat_level,
        failed_attempts_window=threat.failed_attempts_window,
        parallel_sessions=threat.parallel_sessions,
        resource="/login",
        demo_context=demo_context,
    )
    resp = RedirectResponse(url="/", status_code=303)
    set_auth_cookie(resp, token, AUTH_COOKIE_NAME, AUTH_COOKIE_SECURE)
    ensure_session_cookie(request, resp)
    return resp


@app.post("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(AUTH_COOKIE_NAME)
    return resp


@app.get("/me")
async def me(request: Request):
    user = get_authenticated_user(request, auth, AUTH_COOKIE_NAME)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)
    return {"authenticated": True, "username": user.username, "email": user.email, "webid": user.webid}

@app.api_route("/r/{subpath:path}", methods=["GET","PUT","POST","PATCH","DELETE","HEAD","OPTIONS"])
async def guard_r(subpath: str, request: Request):
    request_id = str(uuid.uuid4())
    demo_context = resolve_demo_context(request)
    src_ip, country_code, vpn_suspected = await resolve_network_signals(request)
    user = get_authenticated_user(request, auth, AUTH_COOKIE_NAME)
    webid = request.headers.get("X-WebID") or (user.webid if user else None)
    authn = "header-webid" if request.headers.get("X-WebID") else ("cookie-jwt" if user else "none")
    session_id = resolve_session_id(request, None)
    origin = request.headers.get("Origin")
    append_only = request.headers.get("X-WAC-Append", "false").lower() == "true"

    required_mode = method_to_mode(request.method, request.url.path, append_only)
    target = resource_url_for(RESOURCE_BASE, subpath)

    # Fetch ACL text
    acl_ttl = ""
    acl_ok = True
    try:
        acl_ttl = await fetch_acl_for(RESOURCE_BASE, subpath)
    except Exception:
        acl_ok = False

    decision = None
    if acl_ok:
        decision = allowed_by_acl(
            acl_ttl=acl_ttl,
            resource_url=target,
            required_mode=required_mode,
            webid=webid,
            origin=origin,
        )
    else:
        # If no ACL, deny by default for safety
        decision = Decision(False, "acl_fetch_failed")

    allowed = decision.allowed
    threat, should_alert = detector.assess(
        src_ip=src_ip,
        allowed=allowed,
        webid=webid,
        session_id=session_id,
        country_code=country_code,
        vpn_suspected=vpn_suspected,
        attempted_account=user.username if user else None,
        event_type="resource_access",
    )

    security_event = build_security_event(threat, event_type="resource_access")

    # If denied, block now
    if not allowed:
        event = {
            "request_id": request_id,
            "src_ip": src_ip,
            "http": {"method": request.method, "path": str(request.url.path), "status": 403},
            "agent": {"webid": webid, "authn": authn, "username": user.username if user else None},
            "origin": origin,
            "demo": demo_context,
            "security": security_event,
            "wac": {
                "resource": target,
                "required_mode": required_mode,
                "decision": "deny",
                "reason": decision.reason,
                "matched_authz": decision.matched_authz,
            },
        }
        logger.emit(event)
        maybe_send_threat_alert(
            should_alert=should_alert,
            request_id=request_id,
            src_ip=src_ip,
            webid=webid,
            threat_types=threat.threat_types,
            threat_level=threat.threat_level,
            failed_attempts_window=threat.failed_attempts_window,
            parallel_sessions=threat.parallel_sessions,
            resource=target,
            demo_context=demo_context,
        )
        return PlainTextResponse("Forbidden (WebAuthGuard)\n", status_code=403)

    # Allowed => forward to resource server
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=10) as client:
        upstream = await client.request(
            method=request.method,
            url=target,
            headers=headers,
            content=body,
        )

    event = {
        "request_id": request_id,
        "src_ip": src_ip,
        "http": {"method": request.method, "path": str(request.url.path), "status": upstream.status_code},
        "agent": {"webid": webid, "authn": authn, "username": user.username if user else None},
        "origin": origin,
        "demo": demo_context,
        "security": security_event,
        "wac": {
            "resource": target,
            "required_mode": required_mode,
            "decision": "allow",
            "reason": decision.reason,
            "matched_authz": decision.matched_authz,
        },
    }
    logger.emit(event)
    maybe_send_threat_alert(
        should_alert=should_alert,
        request_id=request_id,
        src_ip=src_ip,
        webid=webid,
        threat_types=threat.threat_types,
        threat_level=threat.threat_level,
        failed_attempts_window=threat.failed_attempts_window,
        parallel_sessions=threat.parallel_sessions,
        resource=target,
        demo_context=demo_context,
    )
    return Response(content=upstream.content, status_code=upstream.status_code, headers=dict(upstream.headers))

@app.post("/alert-webhook")
async def alert_webhook(request: Request):
    payload = await request.json()
    # Keep it simple: forward the alert summary to Telegram
    if telegram_enabled():
        send_telegram(f"WebAuthGuard alert:\n{payload}")
    return {"ok": True}
