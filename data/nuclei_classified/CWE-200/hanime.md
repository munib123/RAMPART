# Vulnerability: Hanime User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hanime.yaml`)

## Description
Hanime user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hanime.tv/channels/{{user}}
```

