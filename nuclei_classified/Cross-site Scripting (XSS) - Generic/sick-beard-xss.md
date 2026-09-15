# Nuclei Template: Sickbeard - Cross-Site Scripting
**Template ID:** sick-beard-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`sick-beard-xss.yaml`)

## Vulnerability Information & PoC

## Description
Sickbeard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E
```

## References
- https://sickbeard.com/
- https://github.com/midgetspy/Sick-Beard
