# Nuclei Template: Samsung WLAN AP WEA453e - Remote Code Execution
**Template ID:** samsung-wlan-ap-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`samsung-wlan-ap-rce.yaml`)

## Vulnerability Information & PoC

## Description
Samsung WLAN AP WEA453e is vulnerable to a pre-auth root remote command execution vulnerability, which means an attacker could run code as root remotely without logging in.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/(download)/tmp/poc.txt
```

## References
- https://omriinbar.medium.com/samsung-wlan-ap-wea453e-vulnerabilities-7aa4a57d4dba
