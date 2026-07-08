# Vulnerability: Slideshare User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slideshare.yaml`)

## Description
Slideshare user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.slideshare.net/{{user}}
```

