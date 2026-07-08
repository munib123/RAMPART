# Vulnerability: eSMTP - Config Discovery
**Classification:** ESMTP
**Source:** Nuclei Template (`esmtprc-config.yaml`)

## Description
eSMTP configuration was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.esmtprc
```

