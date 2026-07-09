# Nuclei Template: Glimpse Diagnostics - Sensitive Data Exposure
**Template ID:** glimpse-data-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`glimpse-data-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Glimpse diagnostics endpoint. Glimpse is a .NET diagnostics tool that reveals detailed request information, server configuration, SQL queries, connection strings, and session data.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/glimpse.axd
GET {{BaseURL}}/Glimpse.axd
```

## References
- https://getglimpse.com/
- https://github.com/Glimpse/Glimpse
