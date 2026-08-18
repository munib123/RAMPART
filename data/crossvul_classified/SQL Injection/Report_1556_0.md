# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1556_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1556_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 80-120 of the vulnerable file.


    session[:login_user_id] = nil
    session[:settings] = nil
    session[:folder_id] = nil
    reset_session

    prms = ApplicationHelper.get_fwd_params(params)
    prms[:controller] = 'login'
    prms[:action] = 'index'
    redirect_to(prms)
  end

  #=== send_password
  #
  #Sends User account information by E-mail.
  #
  def send_password
    Log.add_info(request, params.inspect)

    mail_addr = params[:thetisBoxEdit]
    SqlHelper.validate_token([mail_addr])
    begin
      users = User.where("email='#{mail_addr}'").to_a
    rescue => evar
    end

    if users.nil? or users.empty?
      Log.add_error(request, evar)
      flash[:notice] = 'ERROR:' + t('email.address_not_found')
    else
      user_passwords_h = {}
      users.each do |user|
        newpass = UsersHelper.generate_password
        user.update_attribute(:pass_md5, UsersHelper.generate_digest_pass(user.name, newpass))

        user_passwords_h[user] = newpass
      end

      NoticeMailer.password(user_passwords_h, ApplicationHelper.root_url(request)).deliver;
      flash[:notice] = t('email.sent')
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,9 +97,8 @@
     Log.add_info(request, params.inspect)
 
     mail_addr = params[:thetisBoxEdit]
-    SqlHelper.validate_token([mail_addr])
     begin
-      users = User.where("email='#{mail_addr}'").to_a
+      users = User.where(email: mail_addr).to_a
     rescue => evar
     end
 
```
