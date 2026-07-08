# Vulnerability: Rails Debug Mode
**Classification:** DEBUG
**Source:** Nuclei Template (`rails-debug-mode.yaml`)

## Description
Rails debug mode is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{randstr}}
```

