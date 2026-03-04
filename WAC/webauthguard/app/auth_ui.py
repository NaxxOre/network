from fastapi import Request, Response

try:
    from .auth import AuthStore, AuthUser
except ImportError:
    from auth import AuthStore, AuthUser


def get_authenticated_user(request: Request, auth: AuthStore, auth_cookie_name: str) -> AuthUser | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        user = auth.parse_token(token)
        if user:
            return user

    cookie_token = request.cookies.get(auth_cookie_name)
    if cookie_token:
        user = auth.parse_token(cookie_token)
        if user:
            return user

    return None


def auth_page(title: str, heading: str, action: str, submit_label: str, message: str = "") -> str:
    info = f"<p style='color:#b91c1c;margin:6px 0 12px'>{message}</p>" if message else ""
    extra = (
        "<p style='font-size:14px'>No account? <a href='/signup'>Sign up</a></p>"
        if action == "/login"
        else "<p style='font-size:14px'>Already have an account? <a href='/login'>Login</a></p>"
    )
    email_field = (
        "<label>Email</label><input name='email' type='email' required/>"
        if action == "/signup"
        else ""
    )
    confirm_field = (
        "<label>Confirm Password</label><input name='confirm_password' type='password' required minlength='8'/>"
        if action == "/signup"
        else ""
    )
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'/>
  <meta name='viewport' content='width=device-width, initial-scale=1'/>
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f8fafc; margin: 0; }}
    .wrap {{ max-width: 420px; margin: 64px auto; background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; }}
    h1 {{ margin-top: 0; font-size: 24px; }}
    label {{ display:block; margin: 10px 0 6px; font-weight:600; }}
    input {{ width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; box-sizing: border-box; }}
    button {{ margin-top: 14px; width: 100%; padding: 10px; background: #0f766e; color: white; border: none; border-radius: 6px; cursor: pointer; }}
    .muted {{ color: #475569; font-size: 13px; }}
  </style>
</head>
<body>
  <div class='wrap'>
    <h1>{heading}</h1>
    <p class='muted'>WebAuthGuard account portal</p>
    {info}
    <form method='post' action='{action}'>
      <label>Username</label>
      <input name='username' required minlength='3' />
    {email_field}
      <label>Password</label>
      <input name='password' type='password' required minlength='8'/>
      {confirm_field}
      <input type='hidden' name='session_id' id='session_id'/>
      <input type='hidden' name='country_code_form' id='country_code_form'/>
      <input type='hidden' name='public_ip' id='public_ip'/>
      <input type='hidden' name='vpn_suspected_form' id='vpn_suspected_form'/>
      <button type='submit'>{submit_label}</button>
    </form>
    {extra}
  </div>
  <script>
    (function () {{
      var key = "wac_session_id";
      var sid = localStorage.getItem(key);
      if (!sid) {{
        if (window.crypto && window.crypto.randomUUID) {{
          sid = window.crypto.randomUUID();
        }} else {{
          sid = Math.random().toString(36).slice(2) + Date.now().toString(36);
        }}
        localStorage.setItem(key, sid);
      }}
      var input = document.getElementById("session_id");
      if (input) {{
        input.value = sid;
      }}

      var form = document.querySelector("form[action='{action}']");
      var countryInput = document.getElementById("country_code_form");
      var publicIpInput = document.getElementById("public_ip");
      var vpnInput = document.getElementById("vpn_suspected_form");

      function normalizeCountry(code) {{
        if (!code) {{
          return "";
        }}
        var c = String(code).toUpperCase();
        return /^[A-Z]{{2}}$/.test(c) ? c : "";
      }}

      function normalizeIp(ip) {{
        if (!ip) {{
          return "";
        }}
        var raw = String(ip).trim();
        if (/^\\d{{1,3}}(\\.\\d{{1,3}}){{3}}$/.test(raw)) {{
          return raw;
        }}
        if (/^[0-9a-fA-F:]+$/.test(raw)) {{
          return raw;
        }}
        return "";
      }}

      var netPromise = null;
      function ensureNetworkHints() {{
        if (netPromise) {{
          return netPromise;
        }}

        netPromise = fetch("/net-intel", {{ cache: "no-store" }})
          .then(function (res) {{ return res.json(); }})
          .then(function (data) {{
            if (!data) {{
              return;
            }}

            var ip = normalizeIp(data.public_ip || data.ip);
            var cc = normalizeCountry(data.country_code);
            var vpnDetected = Boolean(data.vpn_suspected);

            if (ip && publicIpInput) {{
              publicIpInput.value = ip;
            }}
            if (cc && countryInput) {{
              countryInput.value = cc;
            }}
            if (vpnInput) {{
              vpnInput.value = vpnDetected ? "true" : "false";
            }}
          }})
          .catch(function () {{
            // Optional enrichment only; form still works without it.
          }});

        return netPromise;
      }}

      ensureNetworkHints();

      if (form) {{
        var resubmitting = false;
        form.addEventListener("submit", function (ev) {{
          if (resubmitting) {{
            return;
          }}

          if (publicIpInput && publicIpInput.value) {{
            return;
          }}

          ev.preventDefault();
          ensureNetworkHints().then(function () {{
            resubmitting = true;
            form.submit();
          }});
        }});
      }}
    }})();
  </script>
</body>
</html>
"""


def set_auth_cookie(resp: Response, token: str, auth_cookie_name: str, auth_cookie_secure: bool) -> None:
    resp.set_cookie(
        auth_cookie_name,
        token,
        httponly=True,
        samesite="lax",
        secure=auth_cookie_secure,
        max_age=86400,
    )
