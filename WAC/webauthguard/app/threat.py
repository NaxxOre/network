import os
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


@dataclass
class ThreatAssessment:
    login_result: str
    success_ip: str | None
    failed_ip: str | None
    possible_threat: bool
    threat_types: list[str]
    threat_level: str
    threat_score: int
    failed_attempts_window: int
    window_seconds: int
    different_ip_login: bool
    distinct_ips_window: int
    vpn_geography_anomaly: bool
    vpn_suspected: bool
    country_code: str | None
    distinct_countries_window: int
    parallel_sessions: int
    parallel_session_violation: bool
    policy_max_parallel_sessions: int
    session_id: str | None
    source_key: str | None
    attempted_account: str | None
    ip_account_key: str | None
    auth_attempt_window_seconds: int
    account_attempts_window: int
    account_failed_attempts_window: int
    account_success_attempts_window: int
    account_failed_attempts_all_window: int
    distinct_failed_accounts_window: int
    distinct_failed_sources_window: int
    account_brute_force: bool
    credential_stuffing: bool
    distributed_account_attack: bool


class SecurityRiskEngine:
    def __init__(self):
        self.window_seconds = _env_int("BRUTE_FORCE_WINDOW_SECONDS", 60)
        self.threshold = _env_int("BRUTE_FORCE_THRESHOLD", 5)
        self.alert_cooldown_seconds = _env_int("BRUTE_FORCE_ALERT_COOLDOWN_SECONDS", 300)

        self.diff_ip_window_seconds = _env_int("DIFFERENT_IP_WINDOW_SECONDS", 600)
        self.diff_ip_threshold = _env_int("DIFFERENT_IP_THRESHOLD", 2)

        self.geo_window_seconds = _env_int("GEO_WINDOW_SECONDS", 1800)
        self.parallel_session_window_seconds = _env_int("PARALLEL_SESSION_WINDOW_SECONDS", 900)
        self.max_parallel_sessions = _env_int("MAX_PARALLEL_SESSIONS", 4)
        self.auth_attempt_window_seconds = _env_int("AUTH_ATTEMPT_WINDOW_SECONDS", 900)
        self.account_brute_force_threshold = _env_int("ACCOUNT_BRUTE_FORCE_THRESHOLD", 6)
        self.credential_stuffing_account_threshold = _env_int("CREDENTIAL_STUFFING_ACCOUNT_THRESHOLD", 5)
        self.distributed_account_attack_source_threshold = _env_int("DISTRIBUTED_ACCOUNT_ATTACK_SOURCE_THRESHOLD", 3)

        self._lock = threading.Lock()
        self._failed_by_ip = defaultdict(deque)
        self._success_ip_by_webid = defaultdict(deque)
        self._country_by_webid = defaultdict(deque)
        self._sessions_by_webid = defaultdict(dict)
        self._auth_attempts_by_ip_account = defaultdict(deque)
        self._auth_failed_by_ip_account = defaultdict(deque)
        self._auth_success_by_ip_account = defaultdict(deque)
        self._auth_failed_by_account = defaultdict(deque)
        self._auth_failed_accounts_by_source = defaultdict(deque)
        self._auth_failed_sources_by_account = defaultdict(deque)
        self._last_alert_by_subject: dict[str, datetime] = {}

    def assess(
        self,
        src_ip: str | None,
        allowed: bool,
        webid: str | None,
        session_id: str | None,
        country_code: str | None,
        vpn_suspected: bool = False,
        attempted_account: str | None = None,
        event_type: str = "resource_access",
    ) -> tuple[ThreatAssessment, bool]:
        ip = (src_ip or "unknown").strip()
        webid_key = (webid or "anonymous").strip()
        sess = (session_id or "").strip() or None
        country = (country_code or "").strip().upper() or None
        account = (attempted_account or "").strip().lower() or None
        source_key = self._source_key(ip, sess) if account and event_type in ("auth_login", "auth_signup") else None
        now = datetime.now(timezone.utc)

        should_alert = False

        with self._lock:
            failures = self._failed_by_ip[ip]
            self._prune_deque(failures, now, self.window_seconds)

            if not allowed:
                failures.append(now)
                self._prune_deque(failures, now, self.window_seconds)

            failed_attempts = len(failures)
            brute_force = failed_attempts >= self.threshold

            distinct_ips = 0
            different_ip_login = False
            if allowed and webid and ip != "unknown":
                ip_events = self._success_ip_by_webid[webid_key]
                ip_events.append((now, ip))
                self._prune_timed_pairs(ip_events, now, self.diff_ip_window_seconds)
                distinct_ips = len({event_ip for _, event_ip in ip_events})
                different_ip_login = distinct_ips >= self.diff_ip_threshold

            distinct_countries = 0
            vpn_geo_anomaly = False
            if allowed and webid and country:
                country_events = self._country_by_webid[webid_key]
                country_events.append((now, country))
                self._prune_timed_pairs(country_events, now, self.geo_window_seconds)
                distinct_countries = len({event_country for _, event_country in country_events})
                vpn_geo_anomaly = distinct_countries > 1

            session_count = 0
            parallel_violation = False
            if allowed and webid and sess:
                sessions = self._sessions_by_webid[webid_key]
                self._prune_session_dict(sessions, now, self.parallel_session_window_seconds)
                sessions[sess] = now
                session_count = len(sessions)
                parallel_violation = session_count > self.max_parallel_sessions

            account_attempts = 0
            account_failed_attempts = 0
            account_success_attempts = 0
            ip_account_key = None
            account_failed_attempts_all = 0
            distinct_failed_accounts = 0
            distinct_failed_sources = 0
            account_brute_force = False
            credential_stuffing = False
            distributed_account_attack = False

            if event_type in ("auth_login", "auth_signup") and account:
                if ip != "unknown":
                    ip_account_key = f"{ip}|{account}"

                    all_events = self._auth_attempts_by_ip_account[ip_account_key]
                    all_events.append(now)
                    self._prune_deque(all_events, now, self.auth_attempt_window_seconds)
                    account_attempts = len(all_events)

                    if allowed:
                        success_events = self._auth_success_by_ip_account[ip_account_key]
                        success_events.append(now)
                        self._prune_deque(success_events, now, self.auth_attempt_window_seconds)
                        account_success_attempts = len(success_events)

                        failed_events = self._auth_failed_by_ip_account[ip_account_key]
                        self._prune_deque(failed_events, now, self.auth_attempt_window_seconds)
                        account_failed_attempts = len(failed_events)
                    else:
                        failed_events = self._auth_failed_by_ip_account[ip_account_key]
                        failed_events.append(now)
                        self._prune_deque(failed_events, now, self.auth_attempt_window_seconds)
                        account_failed_attempts = len(failed_events)

                        success_events = self._auth_success_by_ip_account[ip_account_key]
                        self._prune_deque(success_events, now, self.auth_attempt_window_seconds)
                        account_success_attempts = len(success_events)

                account_failed_events = self._auth_failed_by_account[account]
                if not allowed:
                    account_failed_events.append(now)
                self._prune_deque(account_failed_events, now, self.auth_attempt_window_seconds)
                account_failed_attempts_all = len(account_failed_events)
                account_brute_force = account_failed_attempts_all >= self.account_brute_force_threshold

                effective_source_key = source_key or ip
                source_failed_accounts = self._auth_failed_accounts_by_source[effective_source_key]
                if not allowed:
                    source_failed_accounts.append((now, account))
                self._prune_timed_pairs(source_failed_accounts, now, self.auth_attempt_window_seconds)
                distinct_failed_accounts = len({event_account for _, event_account in source_failed_accounts})
                credential_stuffing = distinct_failed_accounts >= self.credential_stuffing_account_threshold

                account_failed_sources = self._auth_failed_sources_by_account[account]
                if not allowed:
                    account_failed_sources.append((now, effective_source_key))
                self._prune_timed_pairs(account_failed_sources, now, self.auth_attempt_window_seconds)
                distinct_failed_sources = len({event_source for _, event_source in account_failed_sources})
                distributed_account_attack = distinct_failed_sources >= self.distributed_account_attack_source_threshold

            threat_types: list[str] = []
            if brute_force:
                threat_types.append("brute_force")
            if different_ip_login:
                threat_types.append("different_ip_login")
            if vpn_geo_anomaly:
                threat_types.append("vpn_geography_anomaly")
            if vpn_suspected:
                threat_types.append("vpn_proxy_network")
            if parallel_violation:
                threat_types.append("parallel_session_policy_violation")
            if account_brute_force:
                threat_types.append("account_brute_force")
            if credential_stuffing:
                threat_types.append("credential_stuffing")
            if distributed_account_attack:
                threat_types.append("distributed_account_attack")

            possible_threat = len(threat_types) > 0
            threat_score = self._score(
                brute_force=brute_force,
                different_ip_login=different_ip_login,
                vpn_geo_anomaly=vpn_geo_anomaly,
                vpn_suspected=vpn_suspected,
                parallel_violation=parallel_violation,
                account_brute_force=account_brute_force,
                credential_stuffing=credential_stuffing,
                distributed_account_attack=distributed_account_attack,
                failed_attempts=failed_attempts,
                session_count=session_count,
                account_failed_attempts_all=account_failed_attempts_all,
            )
            threat_level = self._level(threat_score)

            if possible_threat:
                alert_subject = webid_key if webid else (source_key or ip)
                last_alert = self._last_alert_by_subject.get(alert_subject)
                if not last_alert or (now - last_alert).total_seconds() >= self.alert_cooldown_seconds:
                    self._last_alert_by_subject[alert_subject] = now
                    should_alert = True

            assessment = ThreatAssessment(
                login_result="success" if allowed else "failed",
                success_ip=ip if allowed else None,
                failed_ip=ip if not allowed else None,
                possible_threat=possible_threat,
                threat_types=threat_types,
                threat_level=threat_level,
                threat_score=threat_score,
                failed_attempts_window=failed_attempts,
                window_seconds=self.window_seconds,
                different_ip_login=different_ip_login,
                distinct_ips_window=distinct_ips,
                vpn_geography_anomaly=vpn_geo_anomaly,
                vpn_suspected=vpn_suspected,
                country_code=country,
                distinct_countries_window=distinct_countries,
                parallel_sessions=session_count,
                parallel_session_violation=parallel_violation,
                policy_max_parallel_sessions=self.max_parallel_sessions,
                session_id=sess,
                source_key=source_key,
                attempted_account=account,
                ip_account_key=ip_account_key,
                auth_attempt_window_seconds=self.auth_attempt_window_seconds,
                account_attempts_window=account_attempts,
                account_failed_attempts_window=account_failed_attempts,
                account_success_attempts_window=account_success_attempts,
                account_failed_attempts_all_window=account_failed_attempts_all,
                distinct_failed_accounts_window=distinct_failed_accounts,
                distinct_failed_sources_window=distinct_failed_sources,
                account_brute_force=account_brute_force,
                credential_stuffing=credential_stuffing,
                distributed_account_attack=distributed_account_attack,
            )
            return assessment, should_alert

    def _source_key(self, ip: str, session_id: str | None) -> str:
        if session_id:
            return f"{ip}|sess:{session_id}"
        return ip

    def _prune_deque(self, events: deque, now: datetime, window_seconds: int) -> None:
        cutoff = now - timedelta(seconds=window_seconds)
        while events and events[0] < cutoff:
            events.popleft()

    def _prune_timed_pairs(self, events: deque, now: datetime, window_seconds: int) -> None:
        cutoff = now - timedelta(seconds=window_seconds)
        while events and events[0][0] < cutoff:
            events.popleft()

    def _prune_session_dict(self, sessions: dict[str, datetime], now: datetime, window_seconds: int) -> None:
        cutoff = now - timedelta(seconds=window_seconds)
        stale = [session_id for session_id, seen in sessions.items() if seen < cutoff]
        for session_id in stale:
            sessions.pop(session_id, None)

    def _score(
        self,
        brute_force: bool,
        different_ip_login: bool,
        vpn_geo_anomaly: bool,
        vpn_suspected: bool,
        parallel_violation: bool,
        account_brute_force: bool,
        credential_stuffing: bool,
        distributed_account_attack: bool,
        failed_attempts: int,
        session_count: int,
        account_failed_attempts_all: int,
    ) -> int:
        score = 0
        if brute_force:
            score += min(50, 30 + max(0, failed_attempts - self.threshold) * 5)
        if different_ip_login:
            score += 20
        if vpn_geo_anomaly:
            score += 30
        if vpn_suspected:
            score += 20
        if parallel_violation:
            score += min(40, 20 + max(0, session_count - self.max_parallel_sessions) * 5)
        if account_brute_force:
            score += min(
                40,
                20 + max(0, account_failed_attempts_all - self.account_brute_force_threshold) * 4,
            )
        if credential_stuffing:
            score += 25
        if distributed_account_attack:
            score += 25
        return min(100, score)

    def _level(self, score: int) -> str:
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "none"
