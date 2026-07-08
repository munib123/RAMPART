# Vulnerability: Glimpse Diagnostics - Sensitive Data Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`glimpse-data-exposure.yaml`)

## Description
Detected Glimpse diagnostics endpoint. Glimpse is a .NET diagnostics tool that reveals detailed request information, server configuration, SQL queries, connection strings, and session data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/glimpse.axd
GET {{BaseURL}}/Glimpse.axd
```

