# Nuclei Template: WordPress Ultimate Member <2.1.7 - Open Redirect
**Template ID:** ultimatemember-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`ultimatemember-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Ultimate Member plugin before 2.1.7 contains an open redirect vulnerability on the registration and login pages via the "redirect_to" GET parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/register/?redirect_to=https://interact.sh/
```

## Remediation
Fixed in 2.1.7.

## References
- https://wpscan.com/vulnerability/97823f41-7614-420e-81b8-9e735e4c203f
