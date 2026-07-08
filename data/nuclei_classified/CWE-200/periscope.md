# Vulnerability: Periscope User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`periscope.yaml`)

## Description
Periscope user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.periscope.tv/{{user}}
```

