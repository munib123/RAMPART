# Nuclei Template: Wiren Board WebUI Panel - Detect
**Template ID:** wiren-board-webui
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`wiren-board-webui.yaml`)

## Vulnerability Information & PoC

## Description
Wiren Board WebUI panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/#!/dashboards
```

