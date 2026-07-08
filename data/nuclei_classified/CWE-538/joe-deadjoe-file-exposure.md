# Vulnerability: Joe Editor DEADJOE File - Exposure
**Classification:** CWE-538
**Source:** Nuclei Template (`joe-deadjoe-file-exposure.yaml`)

## Description
Detected Deadjoe file,this file was created by Joe's Own Editor when a session terminated abnormally. It contained the full contents of the file being edited at the time of the crash, potentially exposing sensitive information such as passwords, configuration files, or credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/DEADJOE
```

