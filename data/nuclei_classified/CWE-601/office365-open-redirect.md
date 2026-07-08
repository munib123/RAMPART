# Vulnerability: Office365 Autodiscover - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`office365-open-redirect.yaml`)

## Description
Office365 Autodiscover contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Secure Mitigation
See the workaround detailed in the Medium post in the references.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/autodiscover/autodiscover.json/v1.0/{{randstr}}@interact.sh?Protocol=Autodiscoverv1
```

