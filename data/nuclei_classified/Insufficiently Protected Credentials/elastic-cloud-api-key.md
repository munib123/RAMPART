# Nuclei Template: Elastic Cloud API Key Detection
**Template ID:** elastic-cloud-api-key
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`elastic-cloud-api-key.yaml`)

## Vulnerability Information & PoC

## Description
Detects Elastic Cloud API keys used for programmatic access to the Elastic Cloud and serverless APIs.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://www.elastic.co/docs/deploy-manage/api-keys/elastic-cloud-api-keys
