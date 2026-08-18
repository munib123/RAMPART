# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1554_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1554_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 41-81 of the vulnerable file.


    if @address.nil?
      @address = Address.new
      @address.name = EmailsHelper.get_sender_exp(disp_name)
      @address.email1 = email
      new
    else
      show
    end
  end

  #=== new
  #
  #Does nothing about showing empty form to create User.
  #
  def new
    if params[:action] == 'new'
      Log.add_info(request, params.inspect)
    end

    render(:action => 'edit', :layout => (!request.xhr?))
  end

  #=== create
  #
  #Creates Address.
  #
  def create
    Log.add_info(request, params.inspect)

    @address = Address.new(params.require(:address).permit(Address::PERMIT_BASE))

    @address = AddressbookHelper.arrange_per_scope(@address, @login_user, params[:scope], params[:groups], params[:teams])
    if @address.nil?
      flash[:notice] = t('msg.need_to_be_owner')
      redirect_to(:controller => 'desktop', :action => 'show')
      return
    end

    begin
      @address.save!
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,8 @@
       Log.add_info(request, params.inspect)
     end
 
+    return unless request.post?
+
     render(:action => 'edit', :layout => (!request.xhr?))
   end
 
@@ -67,6 +69,8 @@
   #
   def create
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     @address = Address.new(params.require(:address).permit(Address::PERMIT_BASE))
 
@@ -106,6 +110,7 @@
     begin
       @address = Address.find(address_id)
     rescue => evar
+      @address = nil
       Log.add_error(request, evar)
       redirect_to(:controller => 'login', :action => 'logout')
       return
@@ -141,6 +146,8 @@
   #
   def update
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     @address = Address.find(params[:id])
     @address.attributes = params[:address]
@@ -242,6 +249,8 @@
   def destroy
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     if params[:check_address].nil?
       list
       render(:action => 'list')
@@ -295,6 +304,8 @@
   #
   def import_csv
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     file = params[:imp_file]
     mode = params[:mode]
@@ -436,7 +447,7 @@
   #
   def check_owner
 
-    return if (params[:id].nil? or params[:id].empty? or @login_user.nil?)
+    return if (params[:id].blank? or @login_user.nil?)
 
     address = Address.find(params[:id])
 
```
