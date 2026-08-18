# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1200-1240 of the vulnerable file.

        @comment.update_attribute(:updated_at, Time.now)
      end
    rescue => evar
      Log.add_error(request, evar)
    end

    render(:partial => 'ajax_comment', :layout => false)
  end

  #=== get_group_users
  #
  #<Ajax>
  #Gets Users in specified Group.
  #
  def get_group_users
    Log.add_info(request, params.inspect)

    @group_id = nil
    if !params[:thetisBoxSelKeeper].nil?
      @group_id = params[:thetisBoxSelKeeper].split(':').last
    elsif !params[:group_id].nil? and !params[:group_id].empty?
      @group_id = params[:group_id]
    end

    @users = Group.get_users @group_id

    render(:partial => 'ajax_select_users', :layout => false)
  end

  #=== wf_issue
  #
  #<Ajax>
  #Issues specified Workflow.
  #
  def wf_issue
    Log.add_info(request, params.inspect)

    begin
      @item = Item.find(params[:id])
      @workflow = @item.workflow
    rescue => evar
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1217,11 +1217,12 @@
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
@@ -1234,7 +1235,7 @@
   def wf_issue
     Log.add_info(request, params.inspect)
 
-    begin
+   begin
       @item = Item.find(params[:id])
       @workflow = @item.workflow
     rescue => evar
@@ -1258,7 +1259,7 @@
     Log.add_info(request, params.inspect)
 
     team_id = params[:team_id]
-    unless team_id.nil? or team_id.empty?
+    unless team_id.blank?
       begin
         @team = Team.find(team_id)
       rescue
@@ -1280,7 +1281,7 @@
 
     if team_members.nil? or team_members.empty?
 
-      unless team_id.nil? or team_id.empty?
+      unless team_id.blank?
         # @team must not be nil.
         @team.save if modified = @team.clear_users
       end
@@ -1289,7 +1290,7 @@
 
       if team_members != users
 
-        if team_id.nil? or team_id.empty?
+        if team_id.blank?
 
           item = Item.find(params[:id])
 
@@ -1359,6 +1360,8 @@
   def change_team_status
     Log.add_info(request, params.inspect)
 
+    SqlHelper.validate_token([params[:status]])
+
     team_id = params[:team_id]
     begin
       team = Team.find(team_id)
@@ -1382,7 +1385,7 @@
   #Filter method to check if the current User is owner of the specified Item.
   #
   def check_owner
-    return if params[:id].nil? or params[:id].empty? or @login_user.nil?
+    return if params[:id].blank? or @login_user.nil?
 
     begin
       owner_id = Item.find(params[:id]).user_id
```
