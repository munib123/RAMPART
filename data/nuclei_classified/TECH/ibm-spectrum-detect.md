# Vulnerability: IBM Spectrum - Detect
**Classification:** TECH
**Source:** Nuclei Template (`ibm-spectrum-detect.yaml`)

## Description
IBM Spectrum products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/BACLIENT
GET {{BaseURL}}/JNLP
```

