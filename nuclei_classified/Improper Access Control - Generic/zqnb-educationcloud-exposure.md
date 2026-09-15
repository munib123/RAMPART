# Nuclei Template: ZhongQing Education Cloud Platform - Information Exposure
**Template ID:** zqnb-educationcloud-exposure
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`zqnb-educationcloud-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Zhongqing Naboo Education Cloud Platform is a deep application supporting teaching and research. Information leakage and unauthorized access exist in the cloud platform system. The password can be reset to 123456 through the leaked user name. The application system does not effectively verify identity on some function pages, allowing direct access and operation on sensitive endpoints. This may enable attackers to obtain sensitive information or reset credentials without proper authorization.

## Impact
Information leakage allows attackers to obtain sensitive data such as usernames. With leaked information, attackers are able to reset passwords and further compromise the system, causing privacy breaches, unauthorized access, or malicious damage to the application system.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/TeacherQuery/SearchTeacherInSiteWithPagerRecords
```

## References
- https://www.pwnwiki.org/index.php?title=%E4%B8%AD%E6%85%B6%E7%B4%8D%E5%8D%9A%E6%95%99%E8%82%B2%E9%9B%B2%E5%B9%B3%E8%87%BA%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%26%E6%9C%AA%E6%8E%88%E6%AC%8A%E8%A8%AA%E5%95%8F%E6%BC%8F%E6%B4%9E
