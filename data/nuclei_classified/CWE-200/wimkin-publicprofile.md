# Vulnerability: Wimkin-PublicProfile User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wimkin-publicprofile.yaml`)

## Description
Wimkin-PublicProfile user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://wimkin.com/{{user}}
```

