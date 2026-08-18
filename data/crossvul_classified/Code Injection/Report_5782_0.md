# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-7 of the vulnerable file.

group :development do
  gem 'yard', require: nil
  gem 'redcarpet', require: nil, platform: :mri
  gem 'fdoc'
end

gem 'sql_origin', groups: [:development, :test]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 group :development do
   gem 'yard', require: nil
   gem 'redcarpet', require: nil, platform: :mri
+
+  gem 'json-schema', '< 2.0.0' # version 2.0 breaks fdoc
   gem 'fdoc'
 end
 
```
