# HackerOne Report: Open redirect and reflected xss in http://youthvoices.adobe.com/community?return_url=[payload her]
**Report ID:** 50379
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi, 
there is a xss vulnerability and open redirect vulnerability in the return_url parameter for the following component:
http://youthvoices.adobe.com/community?return_url=
If a users tries to register or login after following this url:
http://youthvoices.adobe.com/community?return_url=javascript:alert(1)
http://youthvoices.adobe.com/community?return_url=//www.google.com
he will be redirected to google or will trigger the xss vulnerability.

Please see the poc videos below:
https://app.box.com/s/hvjnqyaka1jjarcswltru3qa6sizwz6i
https://app.box.com/s/ntppftcz10v9okwd5xa5wm6h68cjjdzb

I would use this vulnerability to steal users session tokens or to redirect them to a fake login page where i could steal their passwords.
Please let me know what if you think and if you need more details

Kind regards,

nico

## Discussion & Remediation Timeline
