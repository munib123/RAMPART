# Nuclei Template: baserCMS Installation - Exposure
**Template ID:** basercms-install
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`basercms-install.yaml`)

## Vulnerability Information & PoC

## Description
baserCMS installation panel was detected. This indicates an incomplete installation that could be exploited by unauthorized users to set up the CMS with attacker-controlled parameters.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## Remediation
Complete the installation process immediately or restrict access to the installation page.

## References
- https://basercms.net/
