# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 4208_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4208_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1126-1166 of the vulnerable file.

     "Additional <HEAD> tags for most normal pages."),

    ('language_default', 'en', "Default language for user interface and page content, see HelpOnLanguages."),
    ('language_ignore_browser', False, "if True, ignore user's browser language settings, see HelpOnLanguages."),

    ('log_remote_addr', True,
     "if True, log the remote IP address (and maybe hostname)."),
    ('log_reverse_dns_lookups', False,
     "if True, do a reverse DNS lookup on page SAVE."),
    ('log_timing', False,
     "if True, add timing infos to the log output to analyse load conditions"),
    ('log_events_format', 1,
     "0 = no events logging, 1 = standard format (like <= 1.9.7) [default], 2 = extended format"),

    # some dangerous mimetypes (we don't use "content-disposition: inline" for them when a user
    # downloads such attachments, because the browser might execute e.g. Javascript contained
    # in the HTML and steal your moin session cookie or do other nasty stuff)
    ('mimetypes_xss_protect',
     [
       'text/html',
       'application/x-shockwave-flash',
       'application/xhtml+xml',
     ],
     '"content-disposition: inline" isn\'t used for them when a user downloads such attachments'),

    ('mimetypes_embed',
     [
       'application/x-dvi',
       'application/postscript',
       'application/pdf',
       'application/ogg',
       'application/vnd.visio',
       'image/x-ms-bmp',
       'image/svg+xml',
       'image/tiff',
       'image/x-photoshop',
       'audio/mpeg',
       'audio/midi',
       'audio/x-wav',
       'video/fli',
       'video/mpeg',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1143,6 +1143,7 @@
     ('mimetypes_xss_protect',
      [
        'text/html',
+       'image/svg+xml',
        'application/x-shockwave-flash',
        'application/xhtml+xml',
      ],
```
