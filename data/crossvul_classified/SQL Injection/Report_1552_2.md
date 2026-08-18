# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 18-58 of the vulnerable file.


  if $thetis_config[:menu]['req_login_items'] == '1'
    before_filter(:check_login)
  else
    before_filter(:check_login, :except => [:show_tree, :show_url, :get_items, :get_tree, :ajax_get_tree])
  end


  #=== show_tree
  #
  #Shows Folder tree.
  #
  def show_tree
    Log.add_info(request, params.inspect)

    if !@login_user.nil? and @login_user.admin?(User::AUTH_FOLDER)

      @group_id = nil
      if !params[:thetisBoxSelKeeper].nil?
        @group_id = params[:thetisBoxSelKeeper].split(':').last
      elsif !params[:group_id].nil? and !params[:group_id].empty?
        @group_id = params[:group_id]
      end

      @folder_tree = Folder.get_tree_by_group_for_admin(@group_id || '0')
    else
      @folder_tree = Folder.get_tree_for(@login_user)
    end
  end

  #=== ajax_get_tree
  #
  #<Ajax>
  #Gets Folder tree by Ajax.
  #
  def ajax_get_tree
    Log.add_info(request, params.inspect)

    admin = false

    @folder_tree = Folder.get_tree_for(@login_user, admin)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,9 +35,10 @@
       @group_id = nil
       if !params[:thetisBoxSelKeeper].nil?
         @group_id = params[:thetisBoxSelKeeper].split(':').last
-      elsif !params[:group_id].nil? and !params[:group_id].empty?
+      elsif !params[:group_id].blank?
         @group_id = params[:group_id]
       end
+      SqlHelper.validate_token([@group_id])
 
       @folder_tree = Folder.get_tree_by_group_for_admin(@group_id || '0')
     else
@@ -506,6 +507,7 @@
   def get_group_users
     Log.add_info(request, params.inspect)
 
+    SqlHelper.validate_token([params[:id]])
     begin
       @folder = Folder.find(params[:id])
     rescue => evar
@@ -515,11 +517,12 @@
     @group_id = nil
     if !params[:thetisBoxSelKeeper].nil?
       @group_id = params[:thetisBoxSelKeeper].split(':').last
-    elsif !params[:group_id].nil? and !params[:group_id].empty?
+    elsif !params[:group_id].blank?
       @group_id = params[:group_id]
     end
-
-    @users = Group.get_users @group_id
+    SqlHelper.validate_token([@group_id])
+
+    @users = Group.get_users(@group_id)
 
     render(:partial => 'ajax_select_users', :layout => false)
   end
```
