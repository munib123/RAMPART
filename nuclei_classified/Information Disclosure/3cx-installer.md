# Nuclei Template: 3CX Phone System - Installer Page Exposure
**Template ID:** 3cx-installer
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-668
**Source:** Nuclei Template (`3cx-installer.yaml`)

## Vulnerability Information & PoC

## Description
A 3CX Phone System installer or setup wizard page is publicly accessible. This web-based configuration tool is used for initial PBX setup including admin credential creation, SIP trunk configuration, license activation, and network settings. Exposure of this page allows unauthenticated attackers to reconfigure or take over the phone system.

## Impact
An attacker can access the setup wizard to create admin credentials, modify SIP trunk settings, or take complete control of the PBX without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## Remediation
Restrict access to the 3CX installer and configuration pages to trusted internal networks only. Ensure the setup wizard port (5015) and management console are not exposed to the internet.

## References
- https://www.3cx.com/docs/manual/install/
- https://www.3cx.com/
