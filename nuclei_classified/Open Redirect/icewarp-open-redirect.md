# Nuclei Template: IceWarp - Open Redirect
**Template ID:** icewarp-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`icewarp-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
IceWarp open redirect vulnerabilities were detected. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}///interact.sh/%2F..
```

## Remediation
Fixed in 13.0.2.4.

