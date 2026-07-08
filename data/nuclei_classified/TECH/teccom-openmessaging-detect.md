# Vulnerability: TecConnect OpenMessaging Webservice Detection
**Classification:** TECH
**Source:** Nuclei Template (`teccom-openmessaging-detect.yaml`)

## Description
TecCom TecConnect OpenMessaging webservice was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/openmessaging.asmx?wsdl
GET {{BaseURL}}/tecopenmessaging/openmessaging.asmx?wsdl
GET {{BaseURL}}/tomconnect/openmessaging.asmx?wsdl
GET {{BaseURL}}/tomconnect_apo/openmessaging.asmx?wsdl
GET {{BaseURL}}/tompreprod/openmessaging.asmx?wsdl
```

