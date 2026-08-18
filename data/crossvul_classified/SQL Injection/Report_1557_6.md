# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 7-47 of the vulnerable file.

#License::   New BSD License (See LICENSE file)
#URL::   {http&#58;//sysphonic.com/}[http://sysphonic.com/]
#
#Provides utility methods and constants about Items.
#
#== Note:
#
#* 
#
module ItemsHelper

  #=== self.get_next_revision
  #
  #Gets the next revision number for the specified Item-ID.
  #
  #_user_id_:: Target User-ID.
  #_source_id_:: Source Item-ID.
  #return:: Next revision number.
  #
  def self.get_next_revision(user_id, source_id)
    copied_items = Item.where("user_id=#{user_id} and source_id=#{source_id}").order('created_at DESC').to_a

    rev = 0
    copied_items.each do |item|
      rev_ary = item.title.scan(/[#](\d\d\d)$/)
      next if rev_ary.nil?

      rev = rev_ary.first.to_a.first.to_i
      break
    end

    return '#' + sprintf('%03d', rev+1)
  end

  #=== self.get_copies_folder
  #
  #Gets the Copies Folder in My Folder of the specified User.
  #If not found, sets up and initializes it.
  #
  #_user_id_:: Target User-ID.
  #return:: Copies Folder.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,9 @@
   #return:: Next revision number.
   #
   def self.get_next_revision(user_id, source_id)
+
+    SqlHelper.validate_token([user_id, source_id])
+
     copied_items = Item.where("user_id=#{user_id} and source_id=#{source_id}").order('created_at DESC').to_a
 
     rev = 0
@@ -35,7 +38,7 @@
       break
     end
 
-    return '#' + sprintf('%03d', rev+1)
+    return ('#' + sprintf('%03d', rev+1))
   end
 
   #=== self.get_copies_folder
```
