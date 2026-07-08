# Vulnerability: HP LaserJet Professional Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hp-laserjet-detect.yaml`)

## Description
HP LaserJet Professional panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SSI/index.htm
```

