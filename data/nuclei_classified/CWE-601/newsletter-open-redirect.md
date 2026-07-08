# Vulnerability: WordPress Newsletter Manager < 1.5 - Unauthenticated Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`newsletter-open-redirect.yaml`)

## Description
WordPress Newsletter Manager < 1.5 is susceptible to an open redirect vulnerability. The plugin used base64 encoded user input in the appurl parameter without validation to redirect users using the header() PHP function, leading to an open redirect issue.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?wp_nlm=confirmation&appurl=aHR0cDovL2ludGVyYWN0LnNo
```

