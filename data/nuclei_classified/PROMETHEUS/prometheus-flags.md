# Vulnerability: Prometheus flags API endpoint
**Classification:** PROMETHEUS
**Source:** Nuclei Template (`prometheus-flags.yaml`)

## Description
The flags endpoint provides a full path to the configuration file. If the file is stored in the home directory, it may leak a username.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/status/flags
```

