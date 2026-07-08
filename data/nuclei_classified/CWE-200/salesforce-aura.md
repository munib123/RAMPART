# Vulnerability: Salesforce Lightning - API Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`salesforce-aura.yaml`)

## Description
A Salesforce Lightning aura API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/aura
POST {{BaseURL}}/s/sfsites/aura
POST {{BaseURL}}/sfsites/aura
POST {{BaseURL}}/s/aura
POST {{BaseURL}}/s/fact
```

