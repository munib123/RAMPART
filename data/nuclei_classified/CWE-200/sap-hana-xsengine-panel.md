# Vulnerability: SAP HANA XS Engine Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sap-hana-xsengine-panel.yaml`)

## Description
SAP HANA XS Engine admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sap/hana/xs/formLogin/login.html
```

