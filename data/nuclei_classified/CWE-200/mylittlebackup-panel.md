# Vulnerability: myLittleBackup Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mylittlebackup-panel.yaml`)

## Description
myLittleBackup panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/mlb/
GET {{BaseURL}}/mylittlebackup/
```

