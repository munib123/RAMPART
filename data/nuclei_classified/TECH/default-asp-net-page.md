# Vulnerability: ASP.Net Default Page
**Classification:** TECH
**Source:** Nuclei Template (`default-asp-net-page.yaml`)

## Description
Detected default ASP.NET application pages including both traditional and modern versions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

