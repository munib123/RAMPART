# Vulnerability: Parallels HTML5 Client Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`parallels-html-client.yaml`)

## Description
Parallels HTML5 Client login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/RASHTML5Gateway/
```

