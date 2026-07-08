# Vulnerability: Р7-Office 12.5 - Cross-Site Scripting
**Classification:** P7OFFICE
**Source:** Nuclei Template (`p7-office-xss.yaml`)

## Description
A failure to implement proper measures to protect the structure of the web page in the P7-Office corporate server could have allowed a remote attacker to perform a cross-site scripting (XSS) attack.

## Secure Mitigation
Upgrade to the latest version to mitigate this vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Products/Files/HttpHandlers/filehandler.ashx?action=thumb&fileid=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

