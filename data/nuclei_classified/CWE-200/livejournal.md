# Vulnerability: Livejournal User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`livejournal.yaml`)

## Description
Livejournal user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.livejournal.com
```

