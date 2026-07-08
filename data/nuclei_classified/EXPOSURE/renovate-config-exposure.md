# Vulnerability: Renovate Configuration Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`renovate-config-exposure.yaml`)

## Description
Detects exposed Renovate configuration files that may contain sensitive tokens or credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/renovate.json
GET {{BaseURL}}/renovate.json5
GET {{BaseURL}}/.github/renovate.json
GET {{BaseURL}}/.github/renovate.json5
GET {{BaseURL}}/.gitlab/renovate.json
GET {{BaseURL}}/.gitlab/renovate.json5
GET {{BaseURL}}/.renovaterc
GET {{BaseURL}}/.renovaterc.json
GET {{BaseURL}}/.renovaterc.json5
```

