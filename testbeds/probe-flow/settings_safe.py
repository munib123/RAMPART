"""probe-flow settings, fixed: the same names with values the config-flow rules must accept."""
import os

DEBUG = False
GATEWAY_URL = "https://billing.partner.example/charge"
METRICS_URL = "http://127.0.0.1:9100/push"
CORS_ORIGIN = "https://shop.example"
SUPPORT_PASSWORD = os.environ.get("SUPPORT_PASSWORD", "")
