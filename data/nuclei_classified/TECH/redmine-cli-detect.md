# Vulnerability: Detect Redmine CLI Configuration File
**Classification:** TECH
**Source:** Nuclei Template (`redmine-cli-detect.yaml`)

## Description
A small command-line utility to interact with Redmine - https://pypi.org/project/Redmine-CLI/

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.redmine-cli
```

