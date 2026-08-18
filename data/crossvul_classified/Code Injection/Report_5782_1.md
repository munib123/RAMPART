# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-3 of the vulnerable file.

gem 'json'
gem 'git', github: 'RISCfuture/ruby-git'
gem 'user-agent'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,5 @@
 gem 'json'
 gem 'git', github: 'RISCfuture/ruby-git'
 gem 'user-agent'
+
+gem 'safe_yaml'
```
