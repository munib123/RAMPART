# Vulnerability: Aaha chat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aaha-chat.yaml`)

## Description
Aaha chat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.aahachat.org/profile/{{user}}/
```

