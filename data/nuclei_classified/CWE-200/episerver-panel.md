# Vulnerability: Episerver Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`episerver-panel.yaml`)

## Description
Episerver login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/episerver/cms
```

