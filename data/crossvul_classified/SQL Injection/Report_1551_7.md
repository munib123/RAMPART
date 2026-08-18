# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 83-123 of the vulnerable file.

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
      if ret_obj
        array = nodes
      else
        nodes.each do |node|
          array << node.id.to_s
        end
      end
    end

    return array
  end

  #=== get_childs
  #
  #Gets child nodes array of this node.
  #
  #_recursive_:: Specify true if recursive search is required.
  #_ret_obj_:: Flag to require node instances by return.
  #return:: Array of child node-IDs, or nodes if ret_obj is true.
  #
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,7 +100,7 @@
 
     else
 
-      nodes = klass.where("parent_id=#{node_id}").order('xorder ASC, id ASC').to_a
+      nodes = klass.where("parent_id=#{node_id.to_i}").order('xorder ASC, id ASC').to_a
       if ret_obj
         array = nodes
       else
@@ -139,7 +139,7 @@
     else
       con = Marshal.load(Marshal.dump(conditions)) + ' and '
     end
-    con << "(parent_id=#{node_id})"
+    con << "(parent_id=#{node_id.to_i})"
 
     tree[node_id] = klass.where(con).order(order_by).to_a
 
```
