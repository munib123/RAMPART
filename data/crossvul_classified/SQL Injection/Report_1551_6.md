# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 14-54 of the vulnerable file.

#* 
#
module TemplatesHelper

  public::TMPL_ROOT = '$Templates'

  public::TMPL_SYSTEM = 'System'
  public::TMPL_WORKFLOWS = 'Workflows'
  public::TMPL_LOCAL = 'Local'
  public::TMPL_RESEARCH = 'Research'

  #=== self.setup_tmpl_folder
  #
  #Sets up and initializes template folders.
  #
  #return:: Array of Folders. [$Templates, System, Workflows, Local, Research].
  #
  def self.setup_tmpl_folder

    begin
      tmpl_folder = Folder.where("folders.name='#{TMPL_ROOT}'").first
    rescue
    end
    if tmpl_folder.nil?
      # Setup initial template-folders
      folder = Folder.new
      folder.name = TMPL_ROOT
      folder.parent_id = 0
      folder.owner_id = 0
      folder.xtype = Folder::XTYPE_SYSTEM
      folder.save!
      tmpl_folder = folder
    end

    childs = Folder.where("folders.parent_id=#{tmpl_folder.id}").to_a

    # System
    tmpl_system_folder = childs.find{|child| child.name == TMPL_SYSTEM}
    if tmpl_system_folder.nil?
      folder = Folder.new
      folder.name = TMPL_SYSTEM
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
   def self.setup_tmpl_folder
 
     begin
-      tmpl_folder = Folder.where("folders.name='#{TMPL_ROOT}'").first
+      tmpl_folder = Folder.where(name: TMPL_ROOT).first
     rescue
     end
     if tmpl_folder.nil?
@@ -117,7 +117,7 @@
   #
   def self.get_tmpl_folder
 
-    tmpl_folder = Folder.where("folders.name='#{TMPL_ROOT}'").first
+    tmpl_folder = Folder.where(name: TMPL_ROOT).first
 
     if tmpl_folder.nil?
 
@@ -168,10 +168,11 @@
 
     SqlHelper.validate_token([name])
 
-    tmpl_folder = Folder.where("folders.name='#{TMPL_ROOT}'").first
+    tmpl_folder = Folder.where(name: TMPL_ROOT).first
 
     unless tmpl_folder.nil?
-      con = "(parent_id=#{tmpl_folder.id}) and (name='#{name}')"
+      name_quot = SqlHelper.quote(name)
+      con = "(parent_id=#{tmpl_folder.id}) and (name=#{name_quot})"
       begin
         child = Folder.where(con).first
       rescue => evar
```
