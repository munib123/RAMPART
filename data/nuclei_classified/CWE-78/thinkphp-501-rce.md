# Vulnerability: ThinkPHP 5.0.1 - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`thinkphp-501-rce.yaml`)

## Description
ThinkPHP 5.0.1 allows remote unauthenticated attackers to  execute arbitrary code via the 's' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/?s=index/index/index
```

