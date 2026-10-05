"""probe-flow outbound HTTP: the URL's origin decides SSRF; its resolved value decides cleartext."""
from urllib.parse import urlparse

import requests

import settings
import settings_safe

ALLOWED_HOSTS = {"hooks.partner.example"}


def charge(token, amount):
    return requests.post(settings.GATEWAY_URL, data={"token": token, "amount": amount}, timeout=10)


def charge_safe(token, amount):
    return requests.post(settings_safe.GATEWAY_URL, data={"token": token, "amount": amount}, timeout=10)


def push_metrics(payload):
    return requests.post(settings_safe.METRICS_URL, json=payload, timeout=2)


def notify(callback_url, event):
    return requests.post(callback_url, json=event, timeout=5)


def notify_safe(callback_url, event):
    if urlparse(callback_url).hostname not in ALLOWED_HOSTS:
        raise ValueError("callback host not allowed")
    return requests.post(callback_url, json=event, timeout=5)
