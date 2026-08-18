# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4336_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4336_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 1-5 of the vulnerable file.

# frozen_string_literal: true

module Dependabot
  VERSION = "0.125.0"
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 # frozen_string_literal: true
 
 module Dependabot
-  VERSION = "0.125.0"
+  VERSION = "0.125.1"
 end
```
