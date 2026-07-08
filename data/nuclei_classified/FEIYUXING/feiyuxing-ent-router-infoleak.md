# Vulnerability: FeiYuXing Enterprise Router - Information Leakage
**Classification:** FEIYUXING
**Source:** Nuclei Template (`feiyuxing-ent-router-infoleak.yaml`)

## Description
The FeiYuXing Enterprise Router Information Leakage Vulnerability is a critical flaw that allows unauthorized attackers to retrieve sensitive configuration details from the router.

## Secure Mitigation
Update the frimware to the latest version. If your device is out of service.add path /js/../.htpasswd to your WAF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/js/../.htpasswd
```

