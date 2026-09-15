# Nuclei Template: Marimo > 0.9.20 - Proxy Abuse
**Template ID:** marimo-proxy-abuse
**Vulnerability Class:** Uncontrolled Resource Consumption
**Severity:** Medium
**CWE:** CWE-400
**Source:** Nuclei Template (`marimo-proxy-abuse.yaml`)

## Vulnerability Information & PoC

## Description
The /mpl/<port>/<route> endpoint, which is accessible without authentication on default Marimo installations allows for external attackers to reach internal services and arbitrary ports.

## Impact
This vulnerability, as it can be used to bypass firewalls and access internal services that are intended to be local-only. The level of impact depends entirely on what services are running and accessible on the local machine.

## Steps to reproduce / Exploit Payload
```http
GET /mpl/1234 HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Upgrade to Marimo version 0.16.4 or later which adds authentication validation to the

## References
- https://github.com/marimo-team/marimo/security/advisories/GHSA-xjv7-6w92-42r7
- https://github.com/marimo-team/marimo
