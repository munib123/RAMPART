# Nuclei Template: WordPress Newsletter Manager < 1.5 - Unauthenticated Open Redirect
**Template ID:** newsletter-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`newsletter-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Newsletter Manager < 1.5 is susceptible to an open redirect vulnerability. The plugin used base64 encoded user input in the appurl parameter without validation to redirect users using the header() PHP function, leading to an open redirect issue.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?wp_nlm=confirmation&appurl=aHR0cDovL2ludGVyYWN0LnNo
```

## References
- https://wpscan.com/vulnerability/847b3878-da9e-47d6-bc65-3cfd2b3dc1c1
