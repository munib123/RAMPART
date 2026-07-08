# Vulnerability: Apache Tika - Detection
**Classification:** TECH
**Source:** Nuclei Template (`apache-tika-detect.yaml`)

## Description
Detects an Apache Tika server, a toolkit that detects and extracts metadata and text from over a thousand different file types (such as PPT, XLS, and PDF).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/tika
GET {{BaseURL}}/version
```

