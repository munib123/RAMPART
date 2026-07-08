# Vulnerability: WordPress Pie Register < 3.7.2.4 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`pieregister-open-redirect.yaml`)

## Description
WordPress Pie Register < 3.7.2.4 is susceptible to an open redirect vulnerability because the plugin passes unvalidated user input to the wp_redirect() function.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?piereg_logout_url=true&redirect_to=https://interact.sh
```

