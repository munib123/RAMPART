# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 34-74 of the vulnerable file.


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

    key = ActiveRecord::Base.connection.quote("%#{SqlHelper.escape_for_like(keyword)}%")

    con = []
    attr_names.each do |attr_name|
      con << "(#{attr_name} like #{key})"
    end
    sql = con.join(' or ')
    sql = '(' + sql + ')' if con.length > 1
    return sql
  end

  #=== self.escape_for_like
  #
  #Escapes string for like command in SQL.
  #
  #_str_:: Target string.
  #return:: Escaped string.
  #
  def self.escape_for_like(str)

    return nil if str.nil?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
   #
   def self.get_sql_like(attr_names, keyword)
 
-    key = ActiveRecord::Base.connection.quote("%#{SqlHelper.escape_for_like(keyword)}%")
+    key = SqlHelper.quote("%#{SqlHelper.escape_for_like(keyword)}%")
 
     con = []
     attr_names.each do |attr_name|
@@ -74,4 +74,16 @@
     return nil if str.nil?
     return str.to_s.gsub(/([%_])/){"\\" + $1}
   end
+
+  #=== self.quote
+  #
+  #Quotes string.
+  #
+  #_str_:: Target string.
+  #return:: Quoted string.
+  #
+  def self.quote(str)
+
+    return ActiveRecord::Base.connection.quote(str)
+  end
 end
```
