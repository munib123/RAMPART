# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_9
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 605-645 of the vulnerable file.

    user_id = self.user_id

    top_name = (user_id / 100 * 100).to_s

    return File.join(THETIS_MAIL_LOCATION_DIR, top_name, user_id.to_s, sub_folder, self.id.to_s)
  end

  #=== self.trim
  #
  #Trims records within specified number.
  #
  #_user_id_:: Target User-ID.
  #_mail_account_id_:: Target MailAccount-ID.
  #_max_:: Max number.
  #
  def self.trim(user_id, mail_account_id, max)

    SqlHelper.validate_token([user_id, mail_account_id])

    begin
      count = Email.where("mail_account_id=#{mail_account_id}").count
      if count > max
#logger.fatal("[INFO] Email.trim(user_id:#{user_id}, mail_account_id:#{mail_account_id}, max:#{max})")
        over_num = count - max
        emails = []

        # First, empty Trashbox
        user = User.find(user_id)
        trashbox = MailFolder.get_for(user, mail_account_id, MailFolder::XTYPE_TRASH)
        trash_nodes = [trashbox.id.to_s]
        trash_nodes += MailFolder.get_childs(trash_nodes.first, true, false)
        con = "mail_folder_id in (#{trash_nodes.join(',')})"
        emails = Email.where(con).order('updated_at ASC').limit(over_num).to_a

        # Now, remove others
        if emails.length < over_num
          over_num -= emails.length
          emails += Email.where("mail_account_id=#{mail_account_id}").order('updated_at ASC').limit(over_num).to_a
        end

        emails.each do |email|
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -622,7 +622,7 @@
     SqlHelper.validate_token([user_id, mail_account_id])
 
     begin
-      count = Email.where("mail_account_id=#{mail_account_id}").count
+      count = Email.where("mail_account_id=#{mail_account_id.to_i}").count
       if count > max
 #logger.fatal("[INFO] Email.trim(user_id:#{user_id}, mail_account_id:#{mail_account_id}, max:#{max})")
         over_num = count - max
@@ -639,7 +639,7 @@
         # Now, remove others
         if emails.length < over_num
           over_num -= emails.length
-          emails += Email.where("mail_account_id=#{mail_account_id}").order('updated_at ASC').limit(over_num).to_a
+          emails += Email.where("mail_account_id=#{mail_account_id.to_i}").order('updated_at ASC').limit(over_num).to_a
         end
 
         emails.each do |email|
@@ -686,7 +686,7 @@
 #
 #      # Now, remove others
 #      if over_size > 0
-#        emails = Email.where("mail_account_id=#{mail_account_id}").order('updated_at ASC').to_a
+#        emails = Email.where("mail_account_id=#{mail_account_id.to_i}").order('updated_at ASC').to_a
 #        emails.each do |email|
 #          next if email.size.nil?
 #
@@ -762,7 +762,7 @@
 
     SqlHelper.validate_token([user_id])
 
-    con = "user_id=#{user_id}"
+    con = "(user_id=#{user_id.to_i})"
     con << " and (#{add_con})" unless add_con.nil? or add_con.empty?
     emails = Email.where(con).to_a
 
```
