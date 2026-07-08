# Vulnerability: CPAS Management System - Arbitrary File Read
**Classification:** CWE-23
**Source:** Nuclei Template (`cpas-managment-lfi.yaml`)

## Description
The CPAS Audit Management System has been found to contain a vulnerability that allows arbitrary file read. This security flaw can be exploited by attackers to access sensitive files on the server, potentially exposing critical system information. The vulnerability can be triggered by sending a specially crafted HTTP GET request to the endpoint /cpasm4/plugInManController/downPlugs with parameters fileId and fileName, enabling the retrieval of arbitrary files such as /etc/passwd. This issue poses a significant risk to system security and should be addressed immediately to prevent unauthorized access and potential data breaches.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cpasm4/plugInManController/downPlugs?fileId=../../../../etc/passwd&fileName
```

