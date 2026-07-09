# Nuclei Template: GoDaddy Parked Domain - Subdomain Takeover
**Template ID:** godaddy-parked-domain
**Vulnerability Class:** Improper Resource Shutdown or Release
**Severity:** Medium
**CWE:** CWE-404
**Source:** Nuclei Template (`godaddy-parked-domain.yaml`)

## Vulnerability Information & PoC

## Description
Detects potential subdomain takeover when a subdomain's CNAME points to a domain that is parked or listed for sale on GoDaddy. An attacker could purchase the target domain and gain full control over the subdomain, enabling phishing, cookie theft, or malicious content serving.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/lander
```

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
- https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
