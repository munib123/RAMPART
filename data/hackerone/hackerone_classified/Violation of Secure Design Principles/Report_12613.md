# HackerOne Report: X-Content-Type-Options header missing
**Report ID:** 12613
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hello Team

The doesn't have a header settings for X-Content-Type Options which means it is vulnerable to MIME sniffing. The only defined value, "nosniff", prevents Internet Explorer and Google Chrome from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome when downloading extensions. This reduces exposure to drive-by download attacks and sites serving user uploaded content that by clever naming could be treated by MSIE as executable or dynamic HTML files.

## Discussion & Remediation Timeline
