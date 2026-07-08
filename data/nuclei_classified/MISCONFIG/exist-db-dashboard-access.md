# Vulnerability: eXist-DB Dashboard Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`exist-db-dashboard-access.yaml`)

## Description
Detects eXist DB dashboard login endpoint access. eXist DB is a document-oriented database that allows you to store and query XML data. The dashboard is a web interface that allows you to manage the database and view the data.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /exist/apps/dashboard/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password=
```

