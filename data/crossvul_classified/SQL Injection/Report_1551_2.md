# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 153-194 of the vulnerable file.

    return unless request.post?

    begin
      Item.find(params[:id]).destroy
    rescue
    end

    # Get $Templates and its sub folders to update partial division.
    @tmpl_folder, @tmpl_local_folder = TemplatesHelper.get_tmpl_subfolder(TemplatesHelper::TMPL_LOCAL)

    render(:partial => 'ajax_local', :layout => false)
  end

  #=== copy
  #
  #Copies Template.
  #
  def copy
    Log.add_info(request, params.inspect)

    return unless request.post?

    tmpl_id = params[:thetisBoxSelKeeper].split(':').last
    tmpl_item = Item.find(tmpl_id)

    item = tmpl_item.copy(@login_user.id, @login_user.get_my_folder.id)
    if item.public != false
      item.update_attribute(:public, false)
    end

    redirect_to(:controller => 'items', :action => 'edit', :id => item.id)

  rescue => evar
    Log.add_error(request, evar)

    redirect_to(:controller => 'items', :action => 'new')
  end

  #=== ajax_get_tree
  #
  #<Ajax>
  #Gets Template tree by Ajax.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -170,8 +170,6 @@
   def copy
     Log.add_info(request, params.inspect)
 
-    return unless request.post?
-
     tmpl_id = params[:thetisBoxSelKeeper].split(':').last
     tmpl_item = Item.find(tmpl_id)
 
```
