# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 64-104 of the vulnerable file.

      send_file(filepath, :filename => attach.name, :stream => true, :disposition => 'attachment')
    else
      send_data(attach.content, :type => (attach.content_type || 'application/octet-stream')+';charset=UTF-8', :disposition => 'attachment;filename="'+attach.name+'"')
    end
  end

  #=== query
  #
  #Queries available post entries.
  #
  def query
    Log.add_info(request, '')   # Not to show passwords.

    unless @login_user.admin?(User::AUTH_ZEPTAIR)
      render(:text => 'ERROR:' + t('msg.need_to_be_admin'))
      return
    end

    target_user = nil

    SqlHelper.validate_token([params[:user_id], params[:zeptair_id], params[:group_id]])

    unless params[:user_id].blank?
      target_user = User.find(params[:user_id])
    end

    unless params[:zeptair_id].blank?
      zeptair_id = params[:zeptair_id]
      target_user = User.where("zeptair_id=#{zeptair_id}").first
    end

    if target_user.nil?

      if params[:group_id].blank?
        sql = 'select distinct Item.* from items Item, attachments Attachment'
        sql << " where Item.xtype='#{Item::XTYPE_ZEPTAIR_POST}' and Item.id=Attachment.item_id"
        sql << ' order by Item.user_id ASC'
      else
        group_ids = [params[:group_id]]

        if params[:recursive] == 'true'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,33 +81,35 @@
 
     target_user = nil
 
-    SqlHelper.validate_token([params[:user_id], params[:zeptair_id], params[:group_id]])
-
-    unless params[:user_id].blank?
-      target_user = User.find(params[:user_id])
-    end
-
-    unless params[:zeptair_id].blank?
-      zeptair_id = params[:zeptair_id]
+    user_id = params[:user_id]
+    zeptair_id = params[:zeptair_id]
+    group_id = params[:group_id]
+    SqlHelper.validate_token([user_id, zeptair_id, group_id])
+
+    unless user_id.blank?
+      target_user = User.find(user_id)
+    end
+
+    unless zeptair_id.blank?
       target_user = User.where("zeptair_id=#{zeptair_id}").first
     end
 
     if target_user.nil?
 
-      if params[:group_id].blank?
+      if group_id.blank?
         sql = 'select distinct Item.* from items Item, attachments Attachment'
         sql << " where Item.xtype='#{Item::XTYPE_ZEPTAIR_POST}' and Item.id=Attachment.item_id"
         sql << ' order by Item.user_id ASC'
       else
-        group_ids = [params[:group_id]]
+        group_ids = [group_id]
 
         if params[:recursive] == 'true'
-          group_ids += Group.get_childs(params[:group_id], true, false)
+          group_ids += Group.get_childs(group_id, true, false)
         end
 
         groups_con = []
-        group_ids.each do |group_id|
-          groups_con << SqlHelper.get_sql_like(['User.groups'], "|#{@group_id}|")
+        group_ids.each do |grp_id|
+          groups_con << SqlHelper.get_sql_like(['User.groups'], "|#{grp_id}|")
         end
         sql = 'select distinct Item.* from items Item, attachments Attachment, users User'
         sql << " where Item.xtype='#{Item::XTYPE_ZEPTAIR_POST}' and Item.id=Attachment.item_id"
@@ -134,15 +136,20 @@
 
     target_user = nil
 
-    unless params[:user_id].blank?
-      if @login_user.admin?(User::AUTH_ZEPTAIR) or @login_user.id.to_s == params[:user_id].to_s
-        target_user = User.find(params[:user_id])
-      end
-    end
-
-    unless params[:zeptair_id].blank?
-
-      target_user = User.where("zeptair_id=#{params[:zeptair_id]}").first
+    user_id = params[:user_id]
+    zeptair_id = params[:zeptair_id]
+    attachment_id = params[:attachment_id]
+    SqlHelper.validate_token([user_id, zeptair_id, attachment_id])
+
+    unless user_id.blank?
+      if @login_user.admin?(User::AUTH_ZEPTAIR) or @login_user.id.to_s == user_id.to_s
+        target_user = User.find(user_id)
+      end
+    end
+
+    unless zeptair_id.blank?
+
+      target_user = User.where("zeptair_id=#{zeptair_id}").first
 
       unless @login_user.admin?(User::AUTH_ZEPTAIR) or @login_user.id == target_user.id
         target_user = nil
@@ -150,7 +157,7 @@
     end
 
     if target_user.nil?
-      if params[:attachment_id].blank?
+      if attachment_id.blank?
 
         query
         unless @post_items.nil?
@@ -163,7 +170,7 @@
         end
 
       else
-        attach = Attachment.find(params[:attachment_id])
+        attach = Attachment.find(attachment_id)
 
         item = Item.find(attach.item_id)
 
```
