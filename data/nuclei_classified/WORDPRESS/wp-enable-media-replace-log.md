# Vulnerability: WordPress Plugin Enable Media Replace - Log File Exposure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-enable-media-replace-log.yaml`)

## Description
The WordPress plugin "Enable Media Replace" (enable-media-replace) bundles a ShortPixel-based logger that writes a plugin-specific log file into the WordPress uploads directory, typically as `wp-content/uploads/EnableMediaReplace.log`.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/EnableMediaReplace.log
```

