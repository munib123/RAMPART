# Vulnerability: StreamLabs User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`streamlabs.yaml`)

## Description
StreamLabs user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://streamlabs.com/api/v6/user/{{user}}
```

