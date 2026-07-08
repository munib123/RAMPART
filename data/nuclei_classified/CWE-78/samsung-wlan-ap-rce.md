# Vulnerability: Samsung WLAN AP WEA453e - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`samsung-wlan-ap-rce.yaml`)

## Description
Samsung WLAN AP WEA453e is vulnerable to a pre-auth root remote command execution vulnerability, which means an attacker could run code as root remotely without logging in.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/(download)/tmp/poc.txt
```

