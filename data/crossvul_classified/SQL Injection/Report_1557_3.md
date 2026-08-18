# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 15-55 of the vulnerable file.

  layout 'base'

  before_filter(:check_login)
  before_filter(:check_owner, :only => [:rename, :destroy, :move, :get_mails, :empty])
  before_filter(:check_mail_owner, :only => [:get_mail_content, :get_mail_raw])


  #=== show_tree
  #
  #Shows MailFolder tree.
  #
  def show_tree
    if params[:action] == 'show_tree'
      Log.add_info(request, params.inspect)
    end

    con = []
    con << "(user_id=#{@login_user.id})"

    account_xtype = params[:mail_account_xtype]

    unless account_xtype.blank?
      SqlHelper.validate_token([account_xtype])
      con << "(xtype='#{account_xtype}')"
    end
    @mail_accounts = MailAccount.find_all(con.join(' and '))

    mail_account_ids = []
    @mail_accounts.each do |mail_account|

      mail_account_ids << mail_account.id

      if MailFolder.where("mail_account_id=#{mail_account.id}").count <= 0
        @login_user.create_default_mail_folders(mail_account.id)
      end

      Email.destroy_by_user(@login_user.id, "status='#{Email::STATUS_TEMPORARY}'")
    end

    @folder_tree = MailFolder.get_tree_for(@login_user, mail_account_ids)
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,9 +32,9 @@
     con << "(user_id=#{@login_user.id})"
 
     account_xtype = params[:mail_account_xtype]
+    SqlHelper.validate_token([account_xtype])
 
     unless account_xtype.blank?
-      SqlHelper.validate_token([account_xtype])
       con << "(xtype='#{account_xtype}')"
     end
     @mail_accounts = MailAccount.find_all(con.join(' and '))
```
