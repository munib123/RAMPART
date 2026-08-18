# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1556_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1556_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 13-53 of the vulnerable file.

#
#* 
#
module SqlHelper

  #=== self.validate_token
  #
  #Gets query condition with like command of specified attributes.
  #
  #_tokens_:: Target tokens.
  #_extra_chars_:: Extra characters.
  #return:: Query condition.
  #
  def self.validate_token(tokens, extra_chars=nil)

    if extra_chars.nil?
      extra_chars = ''
    else
      extra_chars = Regexp.escape(extra_chars.join())
    end
    regexp = Regexp.new("^[ ]*[a-zA-Z0-9_.@\\-#{extra_chars}]+[ ]*$")

    [tokens].flatten.each do |token|
      next if token.blank?

      if token.to_s.match(regexp).nil?
        raise("[ERROR] SqlHelper.validate_token failed: #{token}")
      end
    end
  end

  #=== self.get_sql_like
  #
  #Gets query condition with like command of specified attributes.
  #
  #_attr_names_:: Attribute names.
  #_keyword_:: Target keyword.
  #return:: Query condition.
  #
  def self.get_sql_like(attr_names, keyword)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,12 +30,13 @@
     else
       extra_chars = Regexp.escape(extra_chars.join())
     end
-    regexp = Regexp.new("^[ ]*[a-zA-Z0-9_.@\\-#{extra_chars}]+[ ]*$")
+    regexp = Regexp.new("^[ ]*[a-zA-Z0-9_#{extra_chars}]+[ ]*$")
 
     [tokens].flatten.each do |token|
       next if token.blank?
 
-      if token.to_s.match(regexp).nil?
+      if token.to_s.match(regexp).nil? \
+          and token.to_s.match(/^[ ]*\d+-\d+-\d+[ ]*$/).nil?
         raise("[ERROR] SqlHelper.validate_token failed: #{token}")
       end
     end
```
