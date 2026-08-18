# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 87-128 of the vulnerable file.

  end

  #=== attachments_without_content
  #
  #Gets Attachments related to this Comment without content.
  #
  #return:: Array of Attachments without content.
  #
  def attachments_without_content

    return [] if self.id.nil?

    sql = 'select id, title, memo, name, size, content_type, comment_id, xorder, location from attachments'
    sql << ' where comment_id=' + self.id.to_s
    sql << ' order by xorder ASC'
    begin
      attachments = Attachment.find_by_sql(sql)
    rescue => evar
      Log.add_error(nil, evar)
    end
    attachments = [] if attachments.nil?
    return attachments
  end

  #=== self.get_toys
  #
  #Gets Toys (desktop items) of specified User.
  #
  #_user_:: Target User.
  #return:: Toys (desktop items) of specified User.
  #
  def self.get_toys(user)

    toys = []
    sql = CommentsHelper.get_list_sql(user)
    unless sql.nil?
      Comment.find_by_sql(sql).each do |comment|
        toys << Toy.copy(nil, comment)
      end
    end

    return toys
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,8 +104,7 @@
     rescue => evar
       Log.add_error(nil, evar)
     end
-    attachments = [] if attachments.nil?
-    return attachments
+    return (attachments || [])
   end
 
   #=== self.get_toys
@@ -160,5 +159,4 @@
     end
     return entries
   end
-
 end
```
