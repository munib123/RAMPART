# Vulnerability: WebTitan Cloud Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`webtitan-cloud-panel.yaml`)

## Description
WebTitan Cloud is a cloud-based web filtering solution that monitors, controls, and protects users and businesses online. It blocks malware, phishing, viruses, ransomware, and malicious sites.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php
```

