# Vulnerability: Woodpecker CI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`woodpecker-ci-panel.yaml`)

## Description
Woodpecker CI panel was detected. Woodpecker is a community fork of Drone CI, providing a simple yet powerful continuous integration platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

