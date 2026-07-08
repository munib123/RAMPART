# Vulnerability: Solar-Log 500 2.8.2 - Incorrect Access Control
**Classification:** CWE-284
**Source:** Nuclei Template (`solar-log-authbypass.yaml`)

## Description
Solar-Log 500 2.8.2 is susceptible to incorrect access control because the web administration server for Solar-Log 500 all versions prior to 2.8.2 Build 52 does not require authentication, which allows arbitrary remote attackers gain administrative privileges by connecting to the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lan.html
```

