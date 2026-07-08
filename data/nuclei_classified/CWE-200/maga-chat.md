# Vulnerability: MAGA-CHAT User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`maga-chat.yaml`)

## Description
MAGA-CHAT user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://maga-chat.com/{{user}}
```

