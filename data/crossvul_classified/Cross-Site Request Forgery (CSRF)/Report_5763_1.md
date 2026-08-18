# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 5763_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5763_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 1-5 of the vulnerable file.

module OmniAuth
  module Facebook
    VERSION = "1.4.1"
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 module OmniAuth
   module Facebook
-    VERSION = "1.4.1"
+    VERSION = "1.5.0"
   end
 end
```
