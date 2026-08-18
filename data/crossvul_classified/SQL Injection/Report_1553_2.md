# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 285-325 of the vulnerable file.

    mail_id = params[:id]

    begin
      @email = Email.find(mail_id)
      render(:partial => 'ajax_mail_content', :layout => false)
    rescue => evar
      Log.add_error(nil, evar)
      render(:text => '')
    end
  end

  #=== get_mail_attachments
  #
  #Gets all attachment-files of the Email.
  #
  def get_mail_attachments
    Log.add_info(request, params.inspect)

    email_id = params[:id]

    email = Email.find_by_id(email_id)
    if email.nil? or email.user_id != @login_user.id
      render(:text => '')
      return
    end

    download_name = "mail_attachments#{email.id}.zip"
    zip_file = email.zip_attachments(params[:enc])

    if zip_file.nil?
      send_data('', :type => 'application/octet-stream;', :disposition => 'attachment;filename="'+download_name+'"')
    else
      filepath = zip_file.path
      send_file(filepath, :filename => download_name, :stream => true, :disposition => 'attachment')
    end
  end

  #=== get_mail_attachment
  #
  #Gets attachment-file of the Email.
  #
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -302,7 +302,7 @@
 
     email_id = params[:id]
 
-    email = Email.find_by_id(email_id)
+    email = Email.find(email_id)
     if email.nil? or email.user_id != @login_user.id
       render(:text => '')
       return
@@ -327,14 +327,20 @@
     Log.add_info(request, params.inspect)
 
     attached_id = params[:id].to_i
-    mail_attach = MailAttachment.find_by_id(attached_id)
+    begin
+      mail_attach = MailAttachment.find(attached_id)
+    rescue => evar
+    end
 
     if mail_attach.nil?
       redirect_to(THETIS_RELATIVE_URL_ROOT + '/404.html')
       return
     end
 
-    email = Email.find_by_id(mail_attach.email_id)
+    begin
+      email = Email.find(mail_attach.email_id)
+    rescue => evar
+    end
     if email.nil? or email.user_id != @login_user.id
       render(:text => '')
       return
@@ -438,7 +444,10 @@
       params[:check_mail].each do |email_id, value|
         next if value != '1'
 
-        email = Email.find_by_id(email_id)
+        begin
+          email = Email.find(email_id)
+        rescue => evar
+        end
         next if email.nil? or (email.user_id != @login_user.id)
 
         if trash_folder.nil? \
@@ -473,7 +482,11 @@
     Log.add_info(request, params.inspect)
 
     folder_id = params[:thetisBoxSelKeeper].split(':').last
-    mail_folder = MailFolder.find_by_id(folder_id)
+    SqlHelper.validate_token([folder_id])
+    begin
+      mail_folder = MailFolder.find(folder_id)
+    rescue => evar
+    end
 
     if folder_id == '0' \
         or mail_folder.nil? \
@@ -541,15 +554,16 @@
   def update_folders_order
     Log.add_info(request, params.inspect)
 
-    order_ary = params[:folders_order]
-
+    order_arr = params[:folders_order]
+
+    SqlHelper.validate_token([params[:id]])
     folders = MailFolder.get_childs(params[:id], false, false)
     # folders must be ordered by xorder ASC.
 
     folders.sort! { |id_a, id_b|
 
-      idx_a = order_ary.index(id_a)
-      idx_b = order_ary.index(id_b)
+      idx_a = order_arr.index(id_a)
+      idx_b = order_arr.index(id_b)
 
       if idx_a.nil? or idx_b.nil?
         idx_a = folders.index(id_a)
```
