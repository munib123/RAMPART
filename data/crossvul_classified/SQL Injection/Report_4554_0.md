# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 4554_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4554_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1-25 of the vulnerable file.

module Administrate
  class Order
    def initialize(attribute = nil, direction = nil)
      @attribute = attribute
      @direction = direction || :asc
    end

    def apply(relation)
      return order_by_association(relation) unless
        reflect_association(relation).nil?

      order = "#{relation.table_name}.#{attribute} #{direction}"

      return relation.reorder(Arel.sql(order)) if
        relation.columns_hash.keys.include?(attribute.to_s)

      relation
    end

    def ordered_by?(attr)
      attr.to_s == attribute.to_s
    end

    def order_params_for(attr)
      {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
   class Order
     def initialize(attribute = nil, direction = nil)
       @attribute = attribute
-      @direction = direction || :asc
+      @direction = sanitize_direction(direction)
     end
 
     def apply(relation)
@@ -34,6 +34,10 @@
 
     attr_reader :attribute
 
+    def sanitize_direction(direction)
+      %w[asc desc].include?(direction.to_s) ? direction.to_sym : :asc
+    end
+
     def reversed_direction_param_for(attr)
       if ordered_by?(attr)
         opposite_direction
@@ -43,7 +47,7 @@
     end
 
     def opposite_direction
-      direction.to_sym == :asc ? :desc : :asc
+      direction == :asc ? :desc : :asc
     end
 
     def order_by_association(relation)
```
