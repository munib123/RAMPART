# Vulnerability: JetBrains WebServers File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jetbrains-webservers.yaml`)

## Description
JetBrains webservers file was detected. The file contains webserver credentials with encoded passwords.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.idea/WebServers.xml
GET {{BaseURL}}/.idea/webServers.xml
GET {{BaseURL}}/.idea/webservers.xml
```

