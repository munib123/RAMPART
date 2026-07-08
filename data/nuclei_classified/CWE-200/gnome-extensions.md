# Vulnerability: Gnome extensions User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gnome-extensions.yaml`)

## Description
Gnome extensions user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://extensions.gnome.org/accounts/profile/{{user}}
```

