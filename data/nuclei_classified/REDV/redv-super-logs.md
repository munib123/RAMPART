# Vulnerability: RED-V Super Digital Signage System RXV-A740R - Log Information Disclosure
**Classification:** REDV
**Source:** Nuclei Template (`redv-super-logs.yaml`)

## Description
The application is vulnerable to sensitive information disclosure vulnerability. An unauthenticated attacker can visit several endpoints and disclose the webserver's log file list containing sensitive system resources and debug log information running on the device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/downloader.log
```

