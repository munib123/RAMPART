# Vulnerability: cgit Web Interface - Detection
**Classification:** TECH
**Source:** Nuclei Template (`cgit-detect.yaml`)

## Description
Detects cgit web interface for Git repositories. cgit is a hyperfast web frontend for Git repositories written in C. It provides a web-based interface to browse Git repositories, view commits, diffs, and files. cgit is designed to be publicly accessible for open source projects. However, detecting cgit instances

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/cgit/
```

