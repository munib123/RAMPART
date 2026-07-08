# Vulnerability: Zimbra Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zimbra-web-client.yaml`)

## Description
Zimbra panel was detected. Zimbra provides open source server and client software for messaging and collaboration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zimbraAdmin/
```

