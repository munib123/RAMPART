# Vulnerability: Moodle Changelog File Detect
**Classification:** MOODLE
**Source:** Nuclei Template (`moodle-changelog.yaml`)

## Description
Moodle has a file which describes API changes in core libraries and APIs, and can be used to discover Moodle version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lib/upgrade.txt
GET {{BaseURL}}/UPGRADING.md
```

