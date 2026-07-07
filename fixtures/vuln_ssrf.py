"""Deliberately vulnerable fixture: SSRF (CWE-918) - logic-level (G3 target)."""
import requests


def fetch_preview(request):
    # URL taken from user input, no allowlist -> SSRF to internal services.
    target = request.args.get("url")
    resp = requests.get(target, timeout=5)
    return resp.text
