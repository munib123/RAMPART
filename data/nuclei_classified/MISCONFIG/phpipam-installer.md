# Vulnerability: PHP IPAM Installation Page - Exposed
**Classification:** MISCONFIG
**Source:** Nuclei Template (`phpipam-installer.yaml`)

## Description
PHP IPAM is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?page=install
```

