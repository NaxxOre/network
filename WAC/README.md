# webauthguard
# WebAuthGuard

WebAuthGuard is a reference implementation of a **Web Access Control (WAC) authorization gateway** in front of a simple resource server.
It validates incoming requests against Turtle ACL rules, forwards authorized traffic to the resource server, and logs authorization decisions to OpenSearch for visibility and auditing.

## Table of Contents
- [Project Scope](#project-scope)
- [Features](#features)
- [General Architecture](#general-architecture)
- [Repository Structure](#repository-structure)
- [Clone, Install, and Set Up](#clone-install-and-set-up)
  - [Set Up on Another Laptop (Windows)](#set-up-on-another-laptop-windows)
  - [Option A: Docker Compose (recommended)](#option-a-docker-compose-recommended)
  - [Option B: Local Python Runtime](#option-b-local-python-runtime)
- [Essential vs Optional Files](#essential-vs-optional-files)
- [Automation Files](#automation-files)
- [Configuration](#configuration)
- [How to Use](#how-to-use)
- [How to Test](#how-to-test)
- [Future Enhancements](#future-enhancements)
- [Troubleshooting](#troubleshooting)

## Project Scope

This project demonstrates a practical MVP for policy-enforced resource access:

- Enforce WAC-style authorization decisions using ACL documents in Turtle format.
- Gate resource operations (`GET`, `PUT`, `POST`, `PATCH`, `DELETE`, etc.) behind a dedicated authorization service.
- Keep ACL and resource management simple and file-backed for easy local experimentation.
- Produce operational telemetry for security monitoring and debugging.

### What this project is ideal for
- Learning and prototyping WebID + ACL authorization flows.
- Demonstrating policy enforcement points in front of HTTP resource servers.
- Building a foundation for more advanced identity and policy systems.

### What this project is not (yet)
- A production-hardened IAM platform.
- A complete Solid server implementation.
- A full policy lifecycle system (versioning, UI, delegated admin workflows).

## Features

### Authorization & Access Control
- Maps HTTP methods to WAC modes:
  - `GET`, `HEAD`, `OPTIONS` -> `read`
  - `PUT`, `POST`, `PATCH`, `DELETE` -> `write`
  - `POST`, `PATCH` + `X-WAC-Append: true` -> `append`
  - `/acl/...` paths -> `control`
- Supports ACL evaluation from Turtle files with `rdflib`.
- Supports rule matching for:
  - `acl:agent` (specific WebID)
  - `acl:agentClass foaf:Agent` (public)
  - `acl:agentClass acl:AuthenticatedAgent` (any authenticated WebID)
  - optional `acl:origin` constraints.
- Deny-by-default behavior when ACL cannot be fetched or no rule matches.

### Gateway / Proxy Behavior
- Exposes guarded endpoint: `http://localhost:8000/r/{path}`.
- For allowed requests, forwards method, headers, and body to resource server.
- For denied requests, returns `403 Forbidden (WebAuthGuard)`.
- Includes built-in authentication web pages:
  - `GET /signup` for account creation
  - `GET /login` for sign-in
  - JWT cookie session (`wac_access_token`) for authenticated requests

### Observability & Alerting
- Emits structured authorization events to OpenSearch indexes:
  - `webauthguard-events-YYYY.MM.DD`
- Includes request metadata (request ID, path, status, WebID, reason, matched authorization).
- Enriches events with security telemetry:
  - `security.login_result` (`success` / `failed`)
  - `security.success_ip`, `security.failed_ip`
  - `security.possible_threat`, `security.threat_level`, `security.threat_score`
  - `security.threat_types` (`brute_force`, `different_ip_login`, `vpn_geography_anomaly`, `parallel_session_policy_violation`)
  - `security.different_ip_login`, `security.distinct_ips_window`
  - `security.vpn_geography_anomaly`, `security.country_code`, `security.distinct_countries_window`
  - `security.parallel_sessions`, `security.parallel_session_violation`, `security.policy_max_parallel_sessions`
  - `security.failed_attempts_window` within a rolling detection window
- Detects brute-force, different-IP logins, VPN/geography anomalies, and parallel-session policy violations.
- Optional Telegram webhook relay for alert notifications.

### Resource Server
- Lightweight FastAPI service for resources and ACL files:
  - `GET/PUT/DELETE /r/{path}`
  - `GET /acl/{path}` reads ACL at `/app/storage/acl/{path}.ttl`
- Adds `Link: </acl/{path}>; rel="acl"` on resource responses.

## General Architecture

```text
Client (curl/app)
   |
   |  HTTP + X-WebID / Origin / X-WAC-Append
   v
WebAuthGuard (FastAPI, :8000)
   |-- fetch ACL --> Resource Server /acl/{path} (:8001)
   |-- evaluate ACL (rdflib)
   |-- allow --> proxy request to Resource Server /r/{path}
   |-- deny --> 403
   |
   |-- log decision --> OpenSearch (:9200)
   |
   '-- optional alert --> Telegram Bot API

OpenSearch Dashboards (:5601) for visualization
```

## Repository Structure

```text
.
├── docker-compose.yml
├── demo.ps1
├── nginx/
│   └── nginx.conf
├── opensearch/
│   └── webauthguard-security-dashboard.ndjson
├── scripts/
│   └── update_auth_ip_account_dashboard.ps1
├── webauthguard/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py             # route orchestration
│       ├── auth.py             # user store + password hashing + JWT
│       ├── auth_ui.py          # auth page rendering + cookie helpers
│       ├── alerts.py           # Telegram alert formatting/sending
│       ├── event_builders.py   # security/auth event payload builders
│       ├── request_utils.py    # source IP + ACL/resource request helpers
│       ├── threat.py           # risk engine + counters
│       ├── wac.py              # ACL parsing and authorization logic
│       ├── oslog.py            # OpenSearch logging helper
│       └── telegram.py         # Telegram transport helper
└── resource_server/
    ├── Dockerfile
    ├── requirements.txt
    └── app/
        ├── main.py       # resource + ACL endpoints
        └── storage/
            ├── r/         # files/resources
            └── acl/       # ACL turtle files (*.ttl)
```

## Clone, Install, and Set Up

### Prerequisites

- Git
- Docker + Docker Compose plugin **or** Python 3.11+

### Set Up on Another Laptop (Windows)

Use these exact steps on the second laptop:

1. Install Docker Desktop and Git.
2. Clone the repository and open PowerShell in the project root (`WAC`).
3. Start the stack:
  ```powershell
  docker compose up --build -d
  ```
4. Check local URLs:
  - `http://localhost/` (login/signup portal via nginx)
  - `http://localhost/dashboards/`
5. For phone/other-device access on same Wi-Fi, allow inbound port 80 (PowerShell **as Administrator**):
  ```powershell
  New-NetFirewallRule -DisplayName "WAC HTTP 80" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Private
  ```
6. Find laptop LAN IP and use it from other devices:
  ```powershell
  Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -ExpandProperty IPv4Address
  ```
  Open `http://<LAN_IP>/` on the other laptop/phone.

---

### Option A: Docker Compose (recommended)

1. **Clone repository**
   ```bash
   git clone <your-repo-url>
   cd WAC
   ```

2. **Start stack**
   ```bash
   docker compose up --build -d
   ```

3. **Verify services**
  - Nginx gateway (LAN entrypoint): `http://localhost/`
  - Nginx -> Dashboards proxy: `http://localhost/dashboards/`
   - Guard: `http://localhost:8000/docs`
   - Resource server: `http://localhost:8001/docs`
   - OpenSearch: `http://localhost:9200`
   - Dashboards: `http://localhost:5601`

4. **Stop stack**
   ```bash
   docker compose down
   ```

5. **Optional one-command demo (auto seeds + checks)**
  ```powershell
  .\demo.ps1
  ```

---

### Option B: Local Python Runtime

Use this if you do not want Docker.

1. **Clone repository**
   ```bash
   git clone <your-repo-url>
   cd WAC
   ```

2. **Create virtual environments and install dependencies**

   Resource server:
   ```bash
   cd resource_server
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   deactivate
   cd ..
   ```

   Guard server:
   ```bash
   cd webauthguard
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   deactivate
   cd ..
   ```

3. **Run resource server (terminal 1)**
   ```bash
   cd resource_server
   source .venv/bin/activate
   uvicorn app.main:app --host 0.0.0.0 --port 8001
   ```

4. **Run guard server (terminal 2)**
   ```bash
   cd webauthguard
   source .venv/bin/activate
   export RESOURCE_BASE=http://localhost:8001
   export OPENSEARCH_URL=http://localhost:9200
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

5. **OpenSearch requirement**
   - You still need an OpenSearch instance for event logging.
   - Simplest path: run OpenSearch with Docker even if apps run locally.

## Essential vs Optional Files

### Essential (keep)

- `docker-compose.yml`
- `nginx/nginx.conf`
- `webauthguard/Dockerfile`
- `webauthguard/requirements.txt`
- `webauthguard/app/*.py` (all runtime modules)
- `resource_server/Dockerfile`
- `resource_server/requirements.txt`
- `resource_server/app/main.py`
- `resource_server/app/storage/` (for ACL/resource data)

### Optional (can delete if you do not need dashboards import/update automation)

- `opensearch/webauthguard-security-dashboard.ndjson` (only for importing a prebuilt dashboard bundle)
- `scripts/update_auth_ip_account_dashboard.ps1` (only for programmatic dashboard patch/export)

### Optional (demo only)

- `demo.ps1` (convenience script; not required for runtime)

### Should usually keep

- `README.md` (operations handover)

## Automation Files

- `demo.ps1`
  - Starts/rebuilds Docker stack
  - Seeds demo resource + ACL
  - Runs allow/deny tests
  - Verifies OpenSearch telemetry fields
- `scripts/update_auth_ip_account_dashboard.ps1`
  - Updates dashboard visualizations for auth IP/account attempts
  - Exports refreshed `.ndjson` bundle

## Configuration

Guard service environment variables:

- `RESOURCE_BASE` (default: `http://resource:8001`)
- `OPENSEARCH_URL` (default: `http://opensearch:9200`)
- `TELEGRAM_ENABLED` (`true` / `false`, default `false`)
- `TELEGRAM_BOT_TOKEN` (required only if Telegram enabled)
- `TELEGRAM_CHAT_ID` (required only if Telegram enabled)
- `BRUTE_FORCE_WINDOW_SECONDS` (default `60`)
- `BRUTE_FORCE_THRESHOLD` (default `5` denied attempts in window)
- `BRUTE_FORCE_ALERT_COOLDOWN_SECONDS` (default `300`)
- `DIFFERENT_IP_WINDOW_SECONDS` (default `600`)
- `DIFFERENT_IP_THRESHOLD` (default `2` distinct successful source IPs in window)
- `GEO_WINDOW_SECONDS` (default `1800`)
- `PARALLEL_SESSION_WINDOW_SECONDS` (default `900`)
- `MAX_PARALLEL_SESSIONS` (default `4`)
- `AUTH_DB_PATH` (default `/app/storage/auth.db`)
- `AUTH_SECRET` (JWT signing secret; set a strong value in production)
- `AUTH_WEBID_BASE` (default `https://local.example/users`)
- `AUTH_TOKEN_TTL_MINUTES` (default `1440`)
- `AUTH_COOKIE_SECURE` (`true` in HTTPS deployments)

Telegram alert settings:

- `TELEGRAM_ENABLED` (`true` / `false`)
- `TELEGRAM_BOT_TOKEN` (from BotFather)
- `TELEGRAM_CHAT_ID` (target chat/user ID)

Security checks implemented for login/signup:

- Passwords hashed with PBKDF2-HMAC-SHA256 + per-user salt
- Password complexity checks (upper/lower/digit/symbol)
- JWT cookie session with `HttpOnly` + `SameSite=Lax` (+ optional `Secure`)
- Login/signup attempts logged to OpenSearch with threat metadata
- Threat alerts to Telegram for suspicious auth patterns
- Per-IP/per-account counters in events:
  - `security.attempted_account`
  - `security.ip_account_key` (`<ip>|<account>`)
  - `security.account_attempts_window`
  - `security.account_failed_attempts_window`
  - `security.account_success_attempts_window`

Request headers used by authorization:

- `X-WebID`: caller WebID identifier used for `acl:agent` / authenticated checks
- `Origin`: matched against optional `acl:origin`
- `X-WAC-Append: true`: treats `POST`/`PATCH` as append intent
- `X-Session-ID`: logical user session identifier (used for parallel session policy)
- `X-Country` (or `CF-IPCountry`): country code used for geography anomaly detection
- `X-Forwarded-For` / `X-Real-IP`: client IP used for different-IP login detection behind proxies

If `X-WebID` is not provided, WebAuthGuard uses authenticated user WebID from login cookie.

### Telegram alerts

When Telegram is enabled, WebAuthGuard sends:

- Alert for **every login attempt** (`/login`) with account, source IP, success/failed result, and per-account attempt counters.
- Alert for threat detections (brute force, different-IP login, geography anomaly, parallel session policy violation).

Quick setup in `docker-compose.yml` for `guard` service:

```yaml
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=<your_bot_token>
TELEGRAM_CHAT_ID=<your_chat_id>
```

Get your chat ID by sending a message to your bot, then opening:

`https://api.telegram.org/bot<your_bot_token>/getUpdates`

After saving config:

```bash
docker compose up --build -d
```

### Verify auth telemetry in dashboard

After failed/successful login attempts, use Discover filter:

- `security.event_type:"auth_login"`
- `security.event_type:"auth_signup"`
- `security.possible_threat:true`

Dev Tools query example:

```json
GET webauthguard-events-*/_search
{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "terms": {
      "security.event_type.keyword": ["auth_login", "auth_signup"]
    }
  }
}
```

## How to Use

### 1) Seed resource and ACL files

Create sample files in `resource_server/app/storage`:

```bash
mkdir -p resource_server/app/storage/r/docs
mkdir -p resource_server/app/storage/acl/docs

cat > resource_server/app/storage/r/docs/report.txt <<'TXT'
Quarterly report
TXT

cat > resource_server/app/storage/acl/docs/report.txt.ttl <<'TTL'
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#read-public>
  a acl:Authorization ;
  acl:accessTo <http://resource:8001/r/docs/report.txt> ;
  acl:mode acl:Read ;
  acl:agentClass foaf:Agent .

<#write-alice>
  a acl:Authorization ;
  acl:accessTo <http://resource:8001/r/docs/report.txt> ;
  acl:mode acl:Write ;
  acl:agent <https://alice.example/profile#me> .
TTL
```

> Note: `acl:accessTo` must match the resource URL as seen by the guard (`http://resource:8001/...` in Docker Compose network).

### 2) Read as public

```bash
curl -i http://localhost:8000/r/docs/report.txt
```

Expected: `200 OK`.

### 2.1) Sign up and login via web pages

- Open `http://localhost:8000/signup` and create a user.
- Login at `http://localhost:8000/login`.
- Check active user via API:

```bash
curl -i http://localhost:8000/me
```

### 3) Try write without WebID

```bash
curl -i -X PUT http://localhost:8000/r/docs/report.txt -d "updated"
```

Expected: `403 Forbidden`.

### 4) Write with authorized WebID

```bash
curl -i -X PUT \
  -H 'X-WebID: https://alice.example/profile#me' \
  http://localhost:8000/r/docs/report.txt \
  -d "updated by alice"
```

Expected: `204 No Content`.

### 5) Inspect logs in OpenSearch

```bash
curl -s "http://localhost:9200/webauthguard-events-*/_search?size=5&sort=@timestamp:desc" | jq
```

### 6) Simulate brute-force attempts (for dashboard demo)

Run multiple denied writes from the same IP:

```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X PUT \
    http://localhost:8000/r/docs/report.txt -d "unauthorized-$i"
done
```

### 7) Simulate different-IP, geography, and parallel-session signals

Use a specific authenticated user and vary session/country headers:

```bash
curl -i -X GET \
  -H 'X-WebID: https://alice.example/profile#me' \
  -H 'X-Session-ID: sess-1' \
  -H 'X-Country: US' \
  http://localhost:8000/r/docs/report.txt

curl -i -X GET \
  -H 'X-WebID: https://alice.example/profile#me' \
  -H 'X-Session-ID: sess-2' \
  -H 'X-Country: DE' \
  http://localhost:8000/r/docs/report.txt
```

Send 5 sessions for the same WebID to trigger `parallel_session_policy_violation`:

```bash
for i in {1..5}; do
  curl -s -o /dev/null -H 'X-WebID: https://alice.example/profile#me' \
    -H "X-Session-ID: sess-$i" -H 'X-Country: US' \
    http://localhost:8000/r/docs/report.txt
done
```

Then query threat events:

```bash
curl -s -X POST "http://localhost:9200/webauthguard-events-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 10,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {
      "term": {"security.possible_threat": true}
    }
  }' | jq
```

## OpenSearch Dashboard Views

1. Create/refresh data view: `webauthguard-events-*` with time field `@timestamp`.
2. In Discover, use these filters:
   - Successful login IPs: `security.login_result:"success"`
   - Failed login IPs: `security.login_result:"failed"`
   - Possible threats: `security.possible_threat:true`
3. Suggested visualizations:
   - Pie/Donut: split by `security.login_result`
   - Top values table: `security.success_ip.keyword`
   - Top values table: `security.failed_ip.keyword`
   - Time series: count of `security.possible_threat:true` over time

Useful Dev Tools queries:

```json
GET webauthguard-events-*/_search
{
  "size": 0,
  "aggs": {
    "success_ips": {"terms": {"field": "security.success_ip.keyword", "size": 10}},
    "failed_ips": {"terms": {"field": "security.failed_ip.keyword", "size": 10}}
  }
}
```

```json
GET webauthguard-events-*/_search
{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "filter": [
        {"term": {"security.possible_threat": true}}
      ]
    }
  }
}
```

### Import prebuilt dashboard

You can import a ready-made dashboard bundle from:

- `opensearch/webauthguard-security-dashboard.ndjson`

Steps in OpenSearch Dashboards:

1. Go to **Management** -> **Saved objects**.
2. Click **Import**.
3. Select `opensearch/webauthguard-security-dashboard.ndjson`.
4. Enable overwrite if prompted, and **do not** choose "Create new copies".
5. Open dashboard **WebAuthGuard Security Overview**.

This bundle includes:

- Data view `webauthguard-events-*`
- Login result distribution chart
- Top failed IPs table
- Top success IPs table
- Possible threats over time chart
- Different IP login events panel
- VPN/geography anomaly events panel
- Parallel session policy violations panel
- Auth login attempts panel
- Auth signup attempts panel
- Auth threat events panel
- Auth IP-account failed attempts table (`security.ip_account_key`)
- Auth IP-account success attempts table (`security.ip_account_key`)

## How to Test

### Manual functional tests (curl)

- **Allow path (public read)**
  ```bash
  curl -i http://localhost:8000/r/docs/report.txt
  ```
- **Deny path (write without WebID)**
  ```bash
  curl -i -X PUT http://localhost:8000/r/docs/report.txt -d "x"
  ```
- **Allow path (write with matching WebID)**
  ```bash
  curl -i -X PUT -H 'X-WebID: https://alice.example/profile#me' \
    http://localhost:8000/r/docs/report.txt -d "x"
  ```
- **Origin-constrained ACL test**
  - add `acl:origin <https://trusted.example>;`
  - call with `-H 'Origin: https://trusted.example'`
  - verify allowed/denied behavior with mismatched origin.

### Basic code health checks

From project root:

```bash
python -m compileall webauthguard/app resource_server/app
```

Optional (if you add tests later):

```bash
pytest -q
```

## Future Enhancements

Recommended improvements to evolve this MVP:

- **Identity & authentication**
  - Replace raw `X-WebID` header trust with verifiable authentication.
  - Integrate OIDC/JWT verification and map claims to WebID.

- **Authorization model**
  - Add support for inherited/default ACLs and `default` semantics.
  - Improve container-level authorization semantics and append/write nuances.
  - Add policy conflict diagnostics and decision traces.

- **Security hardening**
  - Add request signing, mTLS, and stricter header sanitization.
  - Add rate limiting and abuse detection.

- **Operations**
  - Add structured metrics (Prometheus) and richer dashboards.
  - Add alert rules for repeated denials or ACL fetch failures.

- **Developer experience**
  - Add automated unit/integration tests.
  - Add CI pipeline for linting, tests, and container security scans.
  - Provide sample ACL templates and seed scripts.

## Troubleshooting

- **Always getting 403**
  - Verify ACL file exists at `/app/storage/acl/<path>.ttl`.
  - Ensure `acl:accessTo` exactly matches resource URL used by guard.
  - Confirm `X-WebID`/`Origin` headers satisfy ACL constraints.

- **ACL fetch failed**
  - Check guard can reach resource server (`RESOURCE_BASE`).
  - Confirm resource server is running on expected port.

- **No OpenSearch logs visible**
  - Confirm `OPENSEARCH_URL` is reachable from guard.
  - Check OpenSearch container health and index creation.

- **Telegram alerts not sent**
  - Set `TELEGRAM_ENABLED=true` and provide valid bot token/chat ID.
  - Validate outbound network access to Telegram API.



___________________________________________________________________________
Project skeleton created by assistant. Structure:

webauthguard/
  docker-compose.yml
  webauthguard/
    Dockerfile
    requirements.txt
    app/
      main.py
      wac.py
      oslog.py
      telegram.py
  resource_server/
    Dockerfile
    requirements.txt
    app/
      main.py
      storage/
        r/docs/report.txt
        acl/docs/report.txt.ttl

Fill `requirements.txt` and Dockerfile base images before building.
