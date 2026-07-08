# Vulnerability: ZhongQing Education Cloud Platform - Information Exposure
**Classification:** CWE-284
**Source:** Nuclei Template (`zqnb-educationcloud-exposure.yaml`)

## Description
Zhongqing Naboo Education Cloud Platform is a deep application supporting teaching and research. Information leakage and unauthorized access exist in the cloud platform system. The password can be reset to 123456 through the leaked user name. The application system does not effectively verify identity on some function pages, allowing direct access and operation on sensitive endpoints. This may enable attackers to obtain sensitive information or reset credentials without proper authorization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/TeacherQuery/SearchTeacherInSiteWithPagerRecords
```

