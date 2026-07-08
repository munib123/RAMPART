# Vulnerability: JavaMelody Monitoring Exposed
**Classification:** CONFIG
**Source:** Nuclei Template (`java-melody-exposed.yaml`)

## Description
JavaMelody is a tool used to monitor Java or Java EE applications in QA and production environments. JavaMelody was detected on this web application. One option in the dashboard is to "View http sessions". This can be used by an attacker to steal a user's session.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/monitoring
GET {{BaseURL}}/..%3B/monitoring
```

