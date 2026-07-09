# Nuclei Template: Icinga Web 2 Installer Exposure
**Template ID:** icinga-installer
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`icinga-installer.yaml`)

## Vulnerability Information & PoC

## Description
Icinga Web 2 installer/setup wizard is publicly accessible. The setup page at /icingaweb2/setup exposes the configuration wizard which guides through full application configuration including database credentials, authentication backends, and admin account creation. While a setup token is required to proceed, the exposure of the installer itself is a serious misconfiguration that signals an incomplete or improperly secured installation.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/icingaweb2/setup
GET {{BaseURL}}/setup
```

## References
- https://icinga.com/docs/icinga-web/latest/doc/02-Installation/
