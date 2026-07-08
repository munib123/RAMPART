# Vulnerability: Twitcasting User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`twitcasting.yaml`)

## Description
Twitcasting user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://twitcasting.tv/{{user}}
```

