# Vulnerability: Splunk HEC - Detect
**Classification:** TECH
**Source:** Nuclei Template (`splunkhec-detect.yaml`)

## Description
Splunk HCE (HTTP Event Collector (HEC)) was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/services/collector/health
```

