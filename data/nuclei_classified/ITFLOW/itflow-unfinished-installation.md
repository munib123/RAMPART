# Vulnerability: ITFlow Unfinished Installation
**Classification:** ITFLOW
**Source:** Nuclei Template (`itflow-unfinished-installation.yaml`)

## Description
Detected ITFlow setup wizard was exposed with an unfinished installation, allowing attackers to configure the database and create an admin account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/index.php
```

