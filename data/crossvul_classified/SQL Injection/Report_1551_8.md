# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 46-86 of the vulnerable file.

      completed_status = ENTRY_STATUS_SAVED
    elsif target.instance_of?(ZeptairCommand)
      completed_status = ENTRY_STATUS_EXECUTED
    end
    timestamp = ApplicationHelper.get_timestamp(target)
    return "#{target.class}#{ZeptairDistHelper::ACK_CLASS_SEP}#{target.id}#{ACK_ID_SEP}#{timestamp}#{ZeptairDistHelper::ACK_TS_SEP}#{completed_status}"
  end

  #=== self.get_comment_of
  #
  #Gets the reply of the specified User to the Distribution.
  #
  #_item_id_:: Item-ID of Zeptair Distribution.
  #_user_id_:: Target User-ID.
  #return:: Reply as Comment.
  #
  def self.get_comment_of(item_id, user_id)

    SqlHelper.validate_token([item_id, user_id])
    begin
      comment = Comment.where("(user_id=#{user_id}) and (item_id=#{item_id}) and (xtype='#{Comment::XTYPE_DIST_ACK}')").first
    rescue => evar
      Log.add_error(nil, evar)
    end

    return comment
  end

  #=== self.get_ack_array_of
  #
  #Gets the ACK entries of the specified Comment.
  #
  #_comment_:: Target Comment.
  #return:: Array of the ACK entries.
  #
  def self.get_ack_array_of(comment)

    return nil if comment.nil?

    if comment.message.nil?
      entries = []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,7 +63,7 @@
 
     SqlHelper.validate_token([item_id, user_id])
     begin
-      comment = Comment.where("(user_id=#{user_id}) and (item_id=#{item_id}) and (xtype='#{Comment::XTYPE_DIST_ACK}')").first
+      comment = Comment.where("(user_id=#{user_id.to_i}) and (item_id=#{item_id.to_i}) and (xtype='#{Comment::XTYPE_DIST_ACK}')").first
     rescue => evar
       Log.add_error(nil, evar)
     end
@@ -145,7 +145,7 @@
   #
   def self.count_ack_users(item_id)
     SqlHelper.validate_token([item_id])
-    return Comment.where("(item_id=#{item_id}) and (xtype='#{Comment::XTYPE_DIST_ACK}')").count
+    return Comment.where("(item_id=#{item_id.to_i}) and (xtype='#{Comment::XTYPE_DIST_ACK}')").count
   end
 
   #=== self.count_completed_users
@@ -158,7 +158,7 @@
   def self.count_completed_users(item_id)
     SqlHelper.validate_token([item_id])
     ack_msg = ZeptairDistHelper.completed_ack_message(item_id)
-    return Comment.where("(item_id=#{item_id}) and (xtype='#{Comment::XTYPE_DIST_ACK}') and (message='#{ack_msg}')").count
+    return Comment.where("(item_id=#{item_id.to_i}) and (xtype='#{Comment::XTYPE_DIST_ACK}') and (message='#{ack_msg}')").count
   end
 
   #=== self.get_feeds
```
