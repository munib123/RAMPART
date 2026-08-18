# CrossVul Fix Pair: Use of Hard-coded Credentials in ruby
**Pair ID:** 5225_2
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5225_2`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```ruby
Lines 1-12 of the vulnerable file.

def upgrade ta, td, a, d
  a['trove']['db'] = {}
  a['trove']['db']['password'] = nil
  a['trove']['db']['user'] = 'trove'
  a['trove']['db']['database'] = 'trove'
  return a, d
end

def downgrade ta, td, a, d
  a['trove'].delete 'db'
  return a, d
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,12 +1,14 @@
 def upgrade ta, td, a, d
-  a['trove']['db'] = {}
-  a['trove']['db']['password'] = nil
-  a['trove']['db']['user'] = 'trove'
-  a['trove']['db']['database'] = 'trove'
+  unless a.key? "db"
+    a["db"] = {}
+    a["db"]["password"] = nil
+    a["db"]["user"] = "trove"
+    a["db"]["database"] = "trove"
+  end
   return a, d
 end
 
 def downgrade ta, td, a, d
-  a['trove'].delete 'db'
+  a.delete 'db'
   return a, d
 end
```
