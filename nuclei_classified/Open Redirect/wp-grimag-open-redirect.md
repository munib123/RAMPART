# Nuclei Template: WordPress Grimag <1.1.1 - Open Redirection
**Template ID:** wp-grimag-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`wp-grimag-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Grimag theme before 1.1.1 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/Grimag/go.php?https://interact.sh
```

## Remediation
Fixed in 1.1.1.

## References
- https://wpscan.com/vulnerability/db319d4c-7de6-4d36-90e9-86de82e9c03a
