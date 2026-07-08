# Vulnerability: Message me User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`message-me.yaml`)

## Description
Message me user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mssg.me/{{user}}
```

