# Nuclei Template: Kyan Credential - Exposure
**Template ID:** kyan-credential-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`kyan-credential-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Kyan Network login panel was detected. Password and other credential theft is possible via accessing this panel.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/hosts
```

## References
- https://mp.weixin.qq.com/s/6phWjDrGG0pCpGuCdLusIg
