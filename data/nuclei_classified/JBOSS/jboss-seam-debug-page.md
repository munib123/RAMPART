# Vulnerability: Jboss Seam Debug Page Enabled
**Classification:** JBOSS
**Source:** Nuclei Template (`jboss-seam-debug-page.yaml`)

## Description
Jboss Seam Debug Page was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/debug.seam
```

