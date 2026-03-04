# oslog.py
import os
from datetime import datetime, timezone

from opensearchpy import OpenSearch

def now_iso() -> str:
    # ISO 8601 with timezone; safe for time filtering in Dashboards
    return datetime.now(timezone.utc).isoformat()

def index_name() -> str:
    d = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"webauthguard-events-{d}"

class OSLogger:
    def __init__(self):
        url = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")
        # Retry helps when OpenSearch is still starting
        self.client = OpenSearch(
            hosts=[url],
            timeout=30,
            max_retries=5,
            retry_on_timeout=True,
        )

    def emit(self, event: dict) -> None:
        event["@timestamp"] = event.get("@timestamp") or now_iso()
        self.client.index(index=index_name(), body=event)