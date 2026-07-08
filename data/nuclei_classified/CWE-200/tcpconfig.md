# Vulnerability: Rockwell Automation TCP/IP Configuration Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tcpconfig.yaml`)

## Description
TCP/IP configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tcpconfig.html
```

