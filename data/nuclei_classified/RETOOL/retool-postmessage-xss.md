# Vulnerability: Retool Self-Hosted - postMessage XSS via Custom Component Collections
**Classification:** RETOOL
**Source:** Nuclei Template (`retool-postmessage-xss.yaml`)

## Description
Retool Self-Hosted versions 3.284.0 through 3.284.11 contain a cross-site scripting (XSS) vulnerability in the custom component collections iframe handler. The postMessage event listener in custom-component-collections.html accepts messages from any origin without validation and dynamically imports the received code via data:text/javascript URLs, allowing arbitrary JavaScript execution in the Retool instance origin context.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/custom-component-collections.html
GET {{BaseURL}}/{{js-bundle}}
```

