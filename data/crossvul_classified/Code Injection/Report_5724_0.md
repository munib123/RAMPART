# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5724_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5724_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-12 of the vulnerable file.

module Rgpg
  module GemInfo
    MAJOR_VERSION = 0
    MINOR_VERSION = 2
    PATCH_VERSION = 2

    def self.version_string
      [MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION].join('.')
    end
  end
end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
   module GemInfo
     MAJOR_VERSION = 0
     MINOR_VERSION = 2
-    PATCH_VERSION = 2
+    PATCH_VERSION = 3
 
     def self.version_string
       [MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION].join('.')
```
