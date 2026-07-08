# Vulnerability: Sickbeard - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`sick-beard-xss.yaml`)

## Description
Sickbeard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E
```

