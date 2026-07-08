# Vulnerability: OpenAM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openam-panel.yaml`)

## Description
OpenAM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

