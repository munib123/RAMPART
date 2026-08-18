# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 149-183 of the vulnerable file.

        end
      end
    end

    return [tmpl_folder, tmpl_system_folder, tmpl_workflows_folder, tmpl_local_folder, tmpl_q_folder]

  rescue => evar
    Log.add_error(nil, evar)
    return nil
  end

  #=== self.get_tmpl_subfolder
  #
  #Destroys specified Workflow.
  #
  #_name_:: Sub Folder name.
  #return:: Array of Folders. [$Templates, specified sub Folder].
  #
  def self.get_tmpl_subfolder(name)

    tmpl_folder = Folder.where("folders.name='#{TMPL_ROOT}'").first

    unless tmpl_folder.nil?
      con = "(parent_id=#{tmpl_folder.id}) and (name='#{name}')"
      begin
        child = Folder.where(con).first
      rescue => evar
        Log.add_error(nil, evar)
      end
    end

    return [tmpl_folder, child]
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -166,6 +166,8 @@
   #
   def self.get_tmpl_subfolder(name)
 
+    SqlHelper.validate_token([name])
+
     tmpl_folder = Folder.where("folders.name='#{TMPL_ROOT}'").first
 
     unless tmpl_folder.nil?
@@ -179,5 +181,4 @@
 
     return [tmpl_folder, child]
   end
-
 end
```
