# Vulnerability: TrueNAS Panel - Detect
**Classification:** LOGIN
**Source:** Nuclei Template (`truenas-scale-panel.yaml`)

## Description
TrueNAS scale is a free and open-source NAS solution

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/sessions/signin
```

