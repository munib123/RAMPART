# Vulnerability: Apache Struts - OGNL Console
**Classification:** APACHE
**Source:** Nuclei Template (`struts-ognl-console.yaml`)

## Description
This development console allows the evaluation of OGNL expressions that could lead to Remote Command Execution

## Secure Mitigation
Restrict access to the struts console on the production server

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/struts/webconsole.html?debug=console
```

