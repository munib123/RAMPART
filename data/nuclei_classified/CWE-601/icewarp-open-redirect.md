# Vulnerability: IceWarp - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`icewarp-open-redirect.yaml`)

## Description
IceWarp open redirect vulnerabilities were detected. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Secure Mitigation
Fixed in 13.0.2.4.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}///interact.sh/%2F..
```

