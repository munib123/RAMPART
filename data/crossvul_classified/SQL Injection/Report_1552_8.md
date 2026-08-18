# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 346-386 of the vulnerable file.

        @email.update_attributes(update_attrs.permit(Email::PERMIT_BASE))
      end
    rescue => evar
      Log.add_error(request, evar)
    end

    render(:partial => 'ajax_mail_attachments', :layout => false)
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

    submit_url = url_for(:controller => 'send_mails', :action => 'get_group_users')
    render(:partial => 'common/select_users', :layout => false, :locals => {:target_attr => :email, :submit_url => submit_url})
  end

 private
  #=== check_owner
  #
  #Filter method to check if current User is owner of specified Item.
  #
  def check_owner

    return if params[:id].nil? or params[:id].empty? or @login_user.nil?

    email = Email.find(params[:id])

    if !@login_user.admin?(User::AUTH_MAIL) and email.user_id != @login_user.id
      Log.add_check(request, '[check_owner]'+request.to_s)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -363,9 +363,10 @@
     @group_id = nil
     if !params[:thetisBoxSelKeeper].nil?
       @group_id = params[:thetisBoxSelKeeper].split(':').last
-    elsif !params[:group_id].nil? and !params[:group_id].empty?
+    elsif !params[:group_id].blank?
       @group_id = params[:group_id]
     end
+    SqlHelper.validate_token([@group_id])
 
     submit_url = url_for(:controller => 'send_mails', :action => 'get_group_users')
     render(:partial => 'common/select_users', :layout => false, :locals => {:target_attr => :email, :submit_url => submit_url})
@@ -378,7 +379,7 @@
   #
   def check_owner
 
-    return if params[:id].nil? or params[:id].empty? or @login_user.nil?
+    return if params[:id].blank? or @login_user.nil?
 
     email = Email.find(params[:id])
 
```
