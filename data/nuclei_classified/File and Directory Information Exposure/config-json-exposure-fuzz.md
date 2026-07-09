# Nuclei Template: Exposed JSON Configuration Files
**Template ID:** config-json-exposure-fuzz
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Critical
**CWE:** CWE-552
**Source:** Nuclei Template (`config-json-exposure-fuzz.yaml`)

## Vulnerability Information & PoC

## Description
Detects exposed JSON configuration files containing sensitive information including API keys, access tokens, AWS credentials, database configurations, base URLs, file paths, and application settings. These files often contain production configurations and credentials that should not be publicly accessible.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{path}}
```

