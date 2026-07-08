# Vulnerability: Infoblox NIOS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`infoblox-nios-panel.yaml`)

## Description
Infoblox NIOS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/
```

