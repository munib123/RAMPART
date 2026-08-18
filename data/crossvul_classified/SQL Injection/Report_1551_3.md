# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 76-116 of the vulnerable file.

  def query
    Log.add_info(request, '')   # Not to show passwords.

    unless @login_user.admin?(User::AUTH_ZEPTAIR)
      render(:text => 'ERROR:' + t('msg.need_to_be_admin'))
      return
    end

    target_user = nil

    user_id = params[:user_id]
    zeptair_id = params[:zeptair_id]
    group_id = params[:group_id]
    SqlHelper.validate_token([user_id, zeptair_id, group_id])

    unless user_id.blank?
      target_user = User.find(user_id)
    end

    unless zeptair_id.blank?
      target_user = User.where("zeptair_id=#{zeptair_id}").first
    end

    if target_user.nil?

      if group_id.blank?
        sql = 'select distinct Item.* from items Item, attachments Attachment'
        sql << " where Item.xtype='#{Item::XTYPE_ZEPTAIR_POST}' and Item.id=Attachment.item_id"
        sql << ' order by Item.user_id ASC'
      else
        group_ids = [group_id]

        if params[:recursive] == 'true'
          group_ids += Group.get_childs(group_id, true, false)
        end

        groups_con = []
        group_ids.each do |grp_id|
          groups_con << SqlHelper.get_sql_like(['User.groups'], "|#{grp_id}|")
        end
        sql = 'select distinct Item.* from items Item, attachments Attachment, users User'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,7 +93,7 @@
     end
 
     unless zeptair_id.blank?
-      target_user = User.where("zeptair_id=#{zeptair_id}").first
+      target_user = User.where("zeptair_id=#{zeptair_id.to_i}").first
     end
 
     if target_user.nil?
@@ -153,7 +153,7 @@
 
     unless zeptair_id.blank?
 
-      target_user = User.where("zeptair_id=#{zeptair_id}").first
+      target_user = User.where("zeptair_id=#{zeptair_id.to_i}").first
 
       unless @login_user.admin?(User::AUTH_ZEPTAIR) or @login_user.id == target_user.id
         target_user = nil
```
