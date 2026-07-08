# Vulnerability: Icinga Web 2 Installer Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`icinga-installer.yaml`)

## Description
Icinga Web 2 installer/setup wizard is publicly accessible. The setup page at /icingaweb2/setup exposes the configuration wizard which guides through full application configuration including database credentials, authentication backends, and admin account creation. While a setup token is required to proceed, the exposure of the installer itself is a serious misconfiguration that signals an incomplete or improperly secured installation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/icingaweb2/setup
GET {{BaseURL}}/setup
```

