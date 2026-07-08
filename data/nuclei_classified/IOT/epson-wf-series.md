# Vulnerability: Epson WF Series Detection
**Classification:** IOT
**Source:** Nuclei Template (`epson-wf-series.yaml`)

## Description
Searches for Epson WF series printers on the domain

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/PRESENTATION/HTML/TOP/PRTINFO.HTML
```

