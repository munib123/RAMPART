# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_9
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 108-148 of the vulnerable file.

      toy.created_at = ''#folder.created_at
      toy.updated_at = ''#folder.updated_at

    end

    return toy
  end

  #=== self.get_for_user
  #
  #Gets Toys (desktop items) of specified User.
  #
  #_user_:: The target User. If nil, returns empty array.
  #return:: Toys array (desktop items) of specified User.
  #
  def self.get_for_user(user)

    return [] if user.nil?

    toys = Toy.where("user_id=#{user.id}").to_a
    deleted_ary = []

    return [] if toys.nil?

    toys.each do |toy|
      case toy.xtype
        when Toy::XTYPE_ITEM
          item = Item.find_by_id(toy.target_id)
          if item.nil?
            deleted_ary << toy
            next
          end
          Toy.copy(toy, item)

        when Toy::XTYPE_COMMENT
          comment = Comment.find_by_id(toy.target_id)
          if comment.nil?
            deleted_ary << toy
            next
          end
          Toy.copy(toy, comment)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,7 +125,7 @@
     return [] if user.nil?
 
     toys = Toy.where("user_id=#{user.id}").to_a
-    deleted_ary = []
+    deleted_arr = []
 
     return [] if toys.nil?
 
@@ -134,7 +134,7 @@
         when Toy::XTYPE_ITEM
           item = Item.find_by_id(toy.target_id)
           if item.nil?
-            deleted_ary << toy
+            deleted_arr << toy
             next
           end
           Toy.copy(toy, item)
@@ -142,7 +142,7 @@
         when Toy::XTYPE_COMMENT
           comment = Comment.find_by_id(toy.target_id)
           if comment.nil?
-            deleted_ary << toy
+            deleted_arr << toy
             next
           end
           Toy.copy(toy, comment)
@@ -150,7 +150,7 @@
         when Toy::XTYPE_WORKFLOW
           workflow = Workflow.find_by_id(toy.target_id)
           if workflow.nil?
-            deleted_ary << toy
+            deleted_arr << toy
             next
           end
           Toy.copy(toy, workflow)
@@ -158,7 +158,7 @@
         when Toy::XTYPE_SCHEDULE
           schedule = Schedule.find_by_id(toy.target_id)
           if schedule.nil?
-            deleted_ary << toy
+            deleted_arr << toy
             next
           end
           Toy.copy(toy, schedule)
@@ -166,16 +166,16 @@
         when Toy::XTYPE_FOLDER
           folder = Folder.find_by_id(toy.target_id)
           if folder.nil?
-            deleted_ary << toy
+            deleted_arr << toy
             next
           end
           Toy.copy(toy, folder)
       end
     end
 
-    deleted_ary.each do |toy|
-      toys.delete toy
-      Toy.destroy toy.id
+    deleted_arr.each do |toy|
+      toys.delete(toy)
+      Toy.destroy(toy.id)
     end
 
     return toys
```
