# Vulnerability: SQL Server ReportViewer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sql-server-report-viewer.yaml`)

## Description
SQL Server ReportViewer page exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Reports/Pages/Folder.aspx HTTP/1.1
Host: {{Hostname}}

GET /ReportServer/Pages/Folder.aspx HTTP/1.1
Host: {{Hostname}}
```

