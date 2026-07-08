# Vulnerability: Blazor Boot File Disclosure
**Classification:** BLAZOR
**Source:** Nuclei Template (`blazor-boot.yaml`)

## Description
Exposed Blazor Boot (a web framework developed by Microsoft) config file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_framework/blazor.boot.json
```

