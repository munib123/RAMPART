# Vulnerability: Microsoft FrontPage Configuration - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ms-front-page-misconfig.yaml`)

## Description
Microsoft FrontPage Server Extensions configuration files were accessible, exposing version details, directory paths, and other configurations. This was a common misconfiguration on old (2000s) IIS servers with FrontPage Server Extensions installed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_vti_inf.html
GET {{BaseURL}}/_vti_pvt/service.cnf
GET {{BaseURL}}/_vti_pvt/access.cnf
GET {{BaseURL}}/_vti_txt/default.wti/All.cat
```

