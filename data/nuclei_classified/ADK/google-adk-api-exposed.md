# Vulnerability: Google ADK API Exposure
**Classification:** ADK
**Source:** Nuclei Template (`google-adk-api-exposed.yaml`)

## Description
Detects the exposure of the Google Agent Development Kit (ADK) API, which may lead to sensitive information disclosure or unauthorized access.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /apps/my_sample_agent/users/{{randstr}}/sessions/s_123 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"state": {"key1": "value1", "key2": 42}}
```

