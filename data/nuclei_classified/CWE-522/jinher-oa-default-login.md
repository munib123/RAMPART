# Vulnerability: Jinher-OA C6 - Default Admin Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`jinher-oa-default-login.yaml`)

## Description
Jinher-OA C6 default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /c6/Jhsoft.Web.login/AjaxForLogin.aspx HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

type=login&loginCode={{base64("{{username}}")}}&pwd={{base64("{{password}}")}}&
```

