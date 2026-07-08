# Vulnerability: N8n - Config
**Classification:** N8N
**Source:** Nuclei Template (`n8n-config.yaml`)

## Description
The `/rest/settings` endpoint in N8n was publicly exposed, which could have disclosed internal configuration details and sensitive application information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /rest/settings HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

