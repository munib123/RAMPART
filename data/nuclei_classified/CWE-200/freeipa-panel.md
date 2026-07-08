# Vulnerability: FreeIPA Identity Management Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`freeipa-panel.yaml`)

## Description
FreeIPA Identity Management login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ipa/ui/
```

