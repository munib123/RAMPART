# Vulnerability: IBM Decision Server Runtime Panel- Detect
**Classification:** IBM
**Source:** Nuclei Template (`ibm-decision-server-runtime.yaml`)

## Description
IBM Decision Server Runtime was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/DecisionService/
```

