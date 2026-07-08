# Vulnerability: Header Based Generic OOB Interaction
**Classification:** CWE-918
**Source:** Nuclei Template (`oob-header-based-interaction.yaml`)

## Description
The remote server fetched a spoofed URL from the request headers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

