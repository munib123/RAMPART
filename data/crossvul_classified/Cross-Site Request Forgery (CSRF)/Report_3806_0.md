# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 3806_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3806_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 1-5 of the vulnerable file.

class ApplicationController < ActionController::Base
  include Console::Rescue

  protect_from_forgery
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,4 +2,9 @@
   include Console::Rescue
 
   protect_from_forgery
+
+  protected
+    def handle_unverified_request
+      raise Console::AccessDenied, "Request authenticity token does not match session #{session.inspect}"
+    end
 end
```
