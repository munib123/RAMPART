# Nuclei Template: Office365 Autodiscover - Open Redirect
**Template ID:** office365-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`office365-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Office365 Autodiscover contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/autodiscover/autodiscover.json/v1.0/{{randstr}}@interact.sh?Protocol=Autodiscoverv1
```

## Remediation
See the workaround detailed in the Medium post in the references.

## References
- https://medium.com/@heinjame/office365-open-redirect-from-autodiscover-64284d26c168
