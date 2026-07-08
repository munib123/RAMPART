# Vulnerability: XAMPP PHP info Page - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`xampp-phpinfo-detect.yaml`)

## Description
XAMPPHPinfo page was detected. The output of the phpinfo() command can reveal sensitive and detailed PHP environment information.

## Secure Mitigation
Remove PHP Info pages from publicly accessible sites, or restrict access to authorized users only.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

