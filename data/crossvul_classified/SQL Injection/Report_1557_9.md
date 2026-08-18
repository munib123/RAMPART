# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_9
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 61-101 of the vulnerable file.

        end
      end
      break if node.nil?
    end

    return array
  end

  #=== self.get_childs
  #
  #Gets child nodes array of the specified node.
  #
  #_klass_:: Class of tree element.
  #_node_id_:: Target node-ID.
  #_recursive_:: Specify true if recursive search is required.
  #_ret_obj_:: Flag to require node instances by return.
  #return:: Array of child node-IDs, or instances if ret_obj is true.
  #
  def self.get_childs(klass, node_id, recursive, ret_obj)

    array = []

    if recursive

      tree = klass.get_tree(Hash.new, nil, node_id)
      return array if tree.nil?

      tree.each do |parent_id, childs|
        if ret_obj
          array |= childs
        else
          childs.each do |node|
            node_id = node.id.to_s
            array << node_id unless array.include?(node_id)
          end
        end
      end

    else

      nodes = klass.where("parent_id=#{node_id}").order('xorder ASC, id ASC').to_a
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,6 +78,8 @@
   #
   def self.get_childs(klass, node_id, recursive, ret_obj)
 
+    SqlHelper.validate_token([node_id])
+
     array = []
 
     if recursive
@@ -131,6 +133,7 @@
   #
   def self.get_tree(klass, tree, conditions, node_id, order_by)
 
+    SqlHelper.validate_token([node_id])
     if conditions.nil?
       con = ''
     else
```
