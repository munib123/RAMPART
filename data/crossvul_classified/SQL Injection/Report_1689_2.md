# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1689_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1689_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1-5 of the vulnerable file.

module PrefShimaneCms
  class Application
    VERSION = '2.0.0'
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 module PrefShimaneCms
   class Application
-    VERSION = '2.0.0'
+    VERSION = '2.0.1'
   end
 end
```
