# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 51-91 of the vulnerable file.

  #Gets the name of the Copies Folder.
  #
  #return:: Name of the Copies Folder.
  #
  def self.copies_folder
    I18n.t('item.copies_folder')
  end

  #=== is_a_copy?
  #
  #Checks if the Item is a copy of the other Item.
  #
  #_folder_obj_cache_:: Hash to accelerate response. {folder.id, folder}
  #return:: true if the Item is a copy, false otherwise.
  #
  def is_a_copy?(folder_obj_cache=nil)

    return false if self.source_id.nil?

    # Exclude those created from system templates.
    src_item = Item.find_by_id(self.source_id)
    if src_item.nil?
      return true
    else
      return !src_item.in_system_folder?(folder_obj_cache)
    end
  end

  #=== in_system_folder?
  #
  #Checks if the Item is in a system folder.
  #
  #_folder_obj_cache_:: Hash to accelerate response. {folder.id, folder}
  #return:: true if the Item is in a system folder, false otherwise.
  #
  def in_system_folder?(folder_obj_cache=nil)

    folders = self.get_parent_folders(folder_obj_cache)
    system_folder = folders.find{|folder| folder.xtype == Folder::XTYPE_SYSTEM}
    return !system_folder.nil?
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,7 +68,11 @@
     return false if self.source_id.nil?
 
     # Exclude those created from system templates.
-    src_item = Item.find_by_id(self.source_id)
+    begin
+      src_item = Item.find(self.source_id)
+    rescue => evar
+      src_item = nil
+    end
     if src_item.nil?
       return true
     else
```
