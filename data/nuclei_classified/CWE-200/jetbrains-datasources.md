# Vulnerability: Jetbrains IDE DataSources Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jetbrains-datasources.yaml`)

## Description
Jetbrains IDE DataSources configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.idea/dataSources.xml
```

