# Vulnerability: Steller User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`steller.yaml`)

## Description
Steller user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://steller.co/{{user}}
```

