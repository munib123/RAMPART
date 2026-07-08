# Vulnerability: Phoenix Contact CHARX SEC-3XXX AC Controller < 1.7.3 - Multiple Vulnerabilities
**Classification:** PHOENIX-CONTACT
**Source:** Nuclei Template (`phoenix-contact-charx-multiple-vulnerabilities.yaml`)

## Description
Multiple vulnerabilities exist in Phoenix Contact CHARX SEC-3XXX AC Controller versions prior to 1.7.3. Successful exploitation may allow attackers to bypass authentication, disclose sensitive information, or execute arbitrary code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1.0/web/retained-data
```

