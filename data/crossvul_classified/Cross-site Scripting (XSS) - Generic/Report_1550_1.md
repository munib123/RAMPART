# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in yaml
**Pair ID:** 1550_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1550_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```yaml
Lines 1-18 of the vulnerable file.

en:
  errors:
    messages:
      in_between: "must be in between %{min} and %{max}"
      spoofed_media_type: "has an extension that does not match its contents"

  number:
    human:
      storage_units:
        format: "%n %u"
        units:
          byte:
            one:   "Byte"
            other: "Bytes"
          kb: "KB"
          mb: "MB"
          gb: "GB"
          tb: "TB"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
   errors:
     messages:
       in_between: "must be in between %{min} and %{max}"
-      spoofed_media_type: "has an extension that does not match its contents"
+      spoofed_media_type: "has contents that are not what they are reported to be"
 
   number:
     human:
```
