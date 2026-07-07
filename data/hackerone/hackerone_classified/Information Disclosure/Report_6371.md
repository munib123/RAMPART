# HackerOne Report: Lighttpd version disclosure / directory listing
**Report ID:** 6371
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hello there,

the website at http://graphite.khanacademy.org/ isn't configured correctly.

It displays the lighttpd version as well the directory contents.
You should disable these features in your lighttpd.conf / php.ini.

PoC:

```
Index of /

Name	Last Modified	Size	Type
Parent Directory/	 	-  	Directory
index.lighttpd.html	2012-Jun-12 02:46:34	3.4K	text/html
lighttpd/1.4.28
```

Yours sincerely,
Sebastian Neef

## Discussion & Remediation Timeline
