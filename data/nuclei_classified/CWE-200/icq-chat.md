# Vulnerability: Icq-chat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`icq-chat.yaml`)

## Description
Icq-chat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://icq.icqchat.co/members/{{user}}/
```

