# Vulnerability: Codeigniter - .env File Discovery
**Classification:** CWE-552
**Source:** Nuclei Template (`codeigniter-env.yaml`)

## Description
Codeigniter .env file was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

