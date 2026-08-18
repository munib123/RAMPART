# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 396-436 of the vulnerable file.

  #
  #_mail_filter_:: Executed MailFilter.
  #_email_:: Target E-mail.
  #_actions_:: Actions to execute.
  #return:: true if it should be continued, false otherwise.
  #
  def self.execute_actions(mail_filter, email, actions)

    actions.each do |entry|
      verb, val = entry

      result = MailFiltersHelper.send("execute_action_#{verb}", mail_filter, email, val)
      return false unless result
    end
    return true
  end

  def self.execute_action_move(mail_filter, email, val)

    mail_folder_id = val

    mail_folder = MailFolder.find_by_id(mail_folder_id)
    if !mail_folder.nil? and (mail_folder.user_id == email.user_id)
      email.update_attribute(:mail_folder_id, mail_folder_id)
    end

    return true
  end

  def self.execute_action_delete(mail_filter, email, val)

    user = User.find_by_id(email.user_id)

    mail_account_id = mail_filter.mail_account_id
    mail_folder = MailFolder.find_by_id(email.mail_folder_id)
    trash_folder = MailFolder.get_for(user, mail_account_id, MailFolder::XTYPE_TRASH)

    if trash_folder.nil? \
        or mail_folder.id == trash_folder.id \
        or mail_folder.get_parents(false).include?(trash_folder.id.to_s)
      email.destroy
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -413,8 +413,12 @@
   def self.execute_action_move(mail_filter, email, val)
 
     mail_folder_id = val
-
-    mail_folder = MailFolder.find_by_id(mail_folder_id)
+    SqlHelper.validate_token([mail_folder_id])
+
+    begin
+      mail_folder = MailFolder.find(mail_folder_id)
+    rescue => evar
+    end
     if !mail_folder.nil? and (mail_folder.user_id == email.user_id)
       email.update_attribute(:mail_folder_id, mail_folder_id)
     end
```
