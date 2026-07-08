# Vulnerability: JBoss JMX Console Weak Credential Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`jmx-default-login.yaml`)

## Description
JBoss JMX Console default login information was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /jmx-console/ HTTP/1.1
Host: {{Hostname}}

GET /jmx-console/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(user + ':' + pass)}}
```

