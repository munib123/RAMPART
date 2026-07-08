# Vulnerability: Secnet Intelligent Routing System actpt_5g.data - Information Leak
**Classification:** INFO-LEAK
**Source:** Nuclei Template (`secnet-info-leak.yaml`)

## Description
Secnet Intelligent Routing System is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/actpt_5g.data
```

