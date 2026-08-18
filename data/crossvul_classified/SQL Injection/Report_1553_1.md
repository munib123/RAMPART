# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 91-131 of the vulnerable file.


    begin
      @mail_filter = MailFilter.find(mail_filter_id)
    rescue => evar
      Log.add_error(request, evar)
      redirect_to(:controller => 'login', :action => 'logout')
      return
    end
    render(:layout => (!request.xhr?))
  end

  #=== show
  #
  #Shows MailFilter information.
  #
  def show
    if params[:action] == 'show'
      Log.add_info(request, params.inspect)
    end

    @mail_filter = MailFilter.find_by_id(params[:id])
    if @mail_filter.nil?
      render(:text => 'ERROR:' + t('msg.already_deleted', :name => MailFilter.model_name.human))
      return
    else
      if @mail_filter.mail_account.user_id != @login_user.id
        render(:text => 'ERROR:' + t('msg.need_to_be_owner'))
        return
      end
    end
    render(:action => 'show', :layout => (!request.xhr?))
  end

  #=== update
  #
  #Updates MailFilter information.
  #
  def update
    Log.add_info(request, params.inspect)

    attrs = params[:mail_filter]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,7 +108,10 @@
       Log.add_info(request, params.inspect)
     end
 
-    @mail_filter = MailFilter.find_by_id(params[:id])
+    begin
+      @mail_filter = MailFilter.find(params[:id])
+    rescue => evar
+    end
     if @mail_filter.nil?
       render(:text => 'ERROR:' + t('msg.already_deleted', :name => MailFilter.model_name.human))
       return
@@ -225,8 +228,8 @@
   def do_execute
     Log.add_info(request, params.inspect)
 
-    mail_account = MailAccount.find_by_id(params[:mail_account_id])
-    mail_folder = MailFolder.find_by_id(params[:mail_folder_id])
+    mail_account = MailAccount.find(params[:mail_account_id])
+    mail_folder = MailFolder.find(params[:mail_folder_id])
 
     if mail_account.user_id != @login_user.id \
         or mail_folder.user_id != @login_user.id
@@ -258,8 +261,9 @@
     Log.add_info(request, params.inspect)
 
     mail_account_id = params[:mail_account_id]
-
-    @mail_account = MailAccount.find_by_id(mail_account_id)
+    SqlHelper.validate_token([mail_account_id])
+
+    @mail_account = MailAccount.find(mail_account_id)
 
     if @mail_account.user_id != @login_user.id
       flash[:notice] = t('msg.need_to_be_owner')
@@ -285,9 +289,11 @@
     Log.add_info(request, params.inspect)
 
     mail_account_id = params[:mail_account_id]
-    order_ary = params[:mail_filters_order]
-
-    @mail_account = MailAccount.find_by_id(mail_account_id)
+    order_arr = params[:mail_filters_order]
+
+    SqlHelper.validate_token([mail_account_id])
+
+    @mail_account = MailAccount.find(mail_account_id)
 
     if @mail_account.user_id != @login_user.id
       render(:text => 'ERROR:' + t('msg.need_to_be_owner'))
@@ -301,8 +307,8 @@
       id_a = filter_a.id.to_s
       id_b = filter_b.id.to_s
 
-      idx_a = order_ary.index(id_a)
-      idx_b = order_ary.index(id_b)
+      idx_a = order_arr.index(id_a)
+      idx_b = order_arr.index(id_b)
 
       if idx_a.nil? or idx_b.nil?
         idx_a = filters.index(id_a)
```
