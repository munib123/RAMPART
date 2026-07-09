# Nuclei Template: RockMongo 1.1.8 - Cross-Site Scripting
**Template ID:** rockmongo-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`rockmongo-xss.yaml`)

## Vulnerability Information & PoC

## Description
RockMongo 1.1.8 contains a cross-site scripting vulnerability which allows attackers to inject arbitrary JavaScript into the response returned by the application.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/index.php?action=login.index
```

## References
- https://packetstormsecurity.com/files/136658/RockMongo-1.1.8-Cross-Site-Request-Forgery-Cross-Site-Scripting.html
