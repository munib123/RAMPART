# Vulnerability: ELMAH Exposure
**Classification:** LOGS
**Source:** Nuclei Template (`elmah-log-file.yaml`)

## Description
ELMAH (Error Logging Modules and Handlers) is an application-wide error logging facility that is completely pluggable. It can be dynamically added to a running ASP.NET web application, or even all ASP.NET web applications on a machine, without any need for re-compilation or re-deployment. In some cases, the logs expose ASPXAUTH cookies allowing to hijack a logged in administrator session.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/elmah
GET {{BaseURL}}/elmah.axd
```

