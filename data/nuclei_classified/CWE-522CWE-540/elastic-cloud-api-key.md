# Vulnerability: Elastic Cloud API Key Detection
**Classification:** CWE-522,CWE-540
**Source:** Nuclei Template (`elastic-cloud-api-key.yaml`)

## Description
Detects Elastic Cloud API keys used for programmatic access to the Elastic Cloud and serverless APIs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

