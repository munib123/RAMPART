# Vulnerability: IPdiva Mediation Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ipdiva-mediation-panel.yaml`)

## Description
IPdiva Mediation login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/mediation/domains
GET {{BaseURL}}/mediation/authenticate
```

