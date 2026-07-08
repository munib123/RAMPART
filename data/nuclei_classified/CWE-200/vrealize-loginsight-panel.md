# Vulnerability: vRealize Log Insight - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vrealize-loginsight-panel.yaml`)

## Description
Detect vRealize Log Insight login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?loginUrl=%2Findex
```

