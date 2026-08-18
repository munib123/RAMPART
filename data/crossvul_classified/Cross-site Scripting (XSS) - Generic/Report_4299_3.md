# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 4299_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4299_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-8 of the vulnerable file.

class Gon
  module JsonDumper
    def self.dump(object)
      MultiJson.dump object,
        mode: :compat, escape_mode: :xss_safe, time_format: :ruby
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,23 @@
 class Gon
   module JsonDumper
+    # Taken from ERB::Util
+    JSON_ESCAPE_REGEXP	=	/[\u2028\u2029&><]/u
+    JSON_ESCAPE	=	{
+      "&" => '\u0026',
+      ">" => '\u003e',
+      "<" => '\u003c',
+      "\u2028" => '\u2028',
+      "\u2029" => '\u2029'
+    }
+
     def self.dump(object)
-      MultiJson.dump object,
+      dumped_json = MultiJson.dump object,
         mode: :compat, escape_mode: :xss_safe, time_format: :ruby
+      escape(dumped_json)
+    end
+
+    def self.escape(json)
+      json.gsub(JSON_ESCAPE_REGEXP, JSON_ESCAPE)
     end
   end
 end
```
