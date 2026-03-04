import os
import requests

def telegram_enabled() -> bool:
    return os.environ.get("TELEGRAM_ENABLED", "false").lower() == "true"

def send_telegram(text: str) -> bool:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        print("[telegram] skipped: missing bot token or chat id")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        response = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
        if response.status_code >= 400:
            print(f"[telegram] failed: status={response.status_code} body={response.text[:300]}")
            return False
        print("[telegram] sent")
        return True
    except requests.RequestException as exc:
        print(f"[telegram] request error: {exc}")
        return False