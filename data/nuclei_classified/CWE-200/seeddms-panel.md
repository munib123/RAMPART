# Vulnerability: SeedDMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`seeddms-panel.yaml`)

## Description
SeedDMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/out/out.Login.php?referuri=%2Fout%2Fout.ViewFolder.php
GET {{BaseURL}}/dms/out/out.Login.php?referuri=%2Fout%2Fout.ViewFolder.php
```

