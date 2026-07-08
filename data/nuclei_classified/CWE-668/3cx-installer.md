# Vulnerability: 3CX Phone System - Installer Page Exposure
**Classification:** CWE-668
**Source:** Nuclei Template (`3cx-installer.yaml`)

## Description
A 3CX Phone System installer or setup wizard page is publicly accessible. This web-based configuration tool is used for initial PBX setup including admin credential creation, SIP trunk configuration, license activation, and network settings. Exposure of this page allows unauthenticated attackers to reconfigure or take over the phone system.

## Secure Mitigation
Restrict access to the 3CX installer and configuration pages to trusted internal networks only. Ensure the setup wizard port (5015) and management console are not exposed to the internet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

