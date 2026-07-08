# Vulnerability: Jinhe OA_C6_UploadFileDownLoadnew - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`jinhe-oa-c6-upload-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the UploadFileDownLoadnew.aspx interface of Jinhe OA C6. An unauthenticated attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in Extremely unsafe state.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/?FilePath=../Resource/JHFileConfig.ini
```

