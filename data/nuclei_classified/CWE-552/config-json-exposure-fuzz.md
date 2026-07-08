# Vulnerability: Exposed JSON Configuration Files
**Classification:** CWE-552
**Source:** Nuclei Template (`config-json-exposure-fuzz.yaml`)

## Description
Detects exposed JSON configuration files containing sensitive information including API keys, access tokens, AWS credentials, database configurations, base URLs, file paths, and application settings. These files often contain production configurations and credentials that should not be publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{path}}
```

