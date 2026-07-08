# Vulnerability: Dailymotion User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dailymotion.yaml`)

## Description
Dailymotion user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.dailymotion.com/{{user}}
```

