# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 2496_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2496_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-30 of the vulnerable file.

# frozen_string_literal: true
require 'rubygems'

##
# A collection of text-wrangling methods

module Gem::Text

  ##
  # Wraps +text+ to +wrap+ characters and optionally indents by +indent+
  # characters

  def format_text(text, wrap, indent=0)
    result = []
    work = text.dup

    while work.length > wrap do
      if work =~ /^(.{0,#{wrap}})[ \n]/ then
        result << $1.rstrip
        work.slice!(0, $&.length)
      else
        result << work.slice!(0, wrap)
      end
    end

    result << work if work.length.nonzero?
    result.join("\n").gsub(/^/, " " * indent)
  end

  def min3 a, b, c # :nodoc:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,12 +7,19 @@
 module Gem::Text
 
   ##
+  # Remove any non-printable characters and make the text suitable for
+  # printing.
+  def clean_text(text)
+    text.gsub(/[\u0000-\u0008\u000b-\u000c\u000e-\u001F\u007f]/, ".".freeze)
+  end
+
+  ##
   # Wraps +text+ to +wrap+ characters and optionally indents by +indent+
   # characters
 
   def format_text(text, wrap, indent=0)
     result = []
-    work = text.dup
+    work = clean_text(text)
 
     while work.length > wrap do
       if work =~ /^(.{0,#{wrap}})[ \n]/ then
```
