# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in ruby
**Pair ID:** 1926_8
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1926_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```ruby
Lines 1-11 of the vulnerable file.

class VerbServlet < WEBrick::HTTPServlet::AbstractServlet
  %w[HEAD GET POST PUT DELETE].each do |verb|
    eval <<-METHOD
      def do_#{verb}(req, res)
        res.header['X-Request-Method'] = #{verb.dump}
        res.body = #{verb.dump}
      end
    METHOD
  end
end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,11 +1,9 @@
 class VerbServlet < WEBrick::HTTPServlet::AbstractServlet
   %w[HEAD GET POST PUT DELETE].each do |verb|
-    eval <<-METHOD
-      def do_#{verb}(req, res)
-        res.header['X-Request-Method'] = #{verb.dump}
-        res.body = #{verb.dump}
-      end
-    METHOD
+    define_method "do_#{verb}" do |req, res|
+      res.header['X-Request-Method'] = verb
+      res.body = verb
+    end
   end
 end
 
```
