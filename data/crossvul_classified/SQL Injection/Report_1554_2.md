# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1554_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1554_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1-26 of the vulnerable file.

#
#= DesktopController
#
#Original by::   Sysphonic
#Authors::   MORITA Shintaro
#Copyright:: Copyright (c) 2007-2011 MORITA Shintaro, Sysphonic. All rights reserved.
#License::   New BSD License (See LICENSE file)
#URL::   {http&#58;//sysphonic.com/}[http://sysphonic.com/]
#
#The Action-Controller about Desktop.
#
#== Note:
#
#* 
#
class DesktopController < ApplicationController
  protect_from_forgery :except => :drop_file
  layout 'base'

  if $thetis_config[:menu]['req_login_desktop'] == '1'
    before_filter :check_login
  else
    before_filter :check_login, :only => [:edit_config, :update_pref, :post_label, :select_users, :get_group_users, :drop_file]
  end
  before_filter :check_toy_owner, :only => [:drop_on_recyclebox, :on_toys_moved, :update_label]

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 #
 #Original by::   Sysphonic
 #Authors::   MORITA Shintaro
-#Copyright:: Copyright (c) 2007-2011 MORITA Shintaro, Sysphonic. All rights reserved.
+#Copyright:: Copyright (c) 2007-2015 MORITA Shintaro, Sysphonic. All rights reserved.
 #License::   New BSD License (See LICENSE file)
 #URL::   {http&#58;//sysphonic.com/}[http://sysphonic.com/]
 #
@@ -36,6 +36,8 @@
   def drop_file
     Log.add_info(request, '')   # Not to show passwords.
 
+    return unless request.post?
+
     if params[:file].nil? or params[:file].size <= 0
       render(:text => '')
       return
@@ -126,6 +128,8 @@
   def update_pref
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     desktop = Desktop.get_for(@login_user, true)
 
     params[:desktop].delete(:user_id)
@@ -145,9 +149,11 @@
   def update_config
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     @yaml = ApplicationHelper.get_config_yaml
 
-    unless params[:desktop].nil? or params[:desktop].empty?
+    unless params[:desktop].blank?
       @yaml[:desktop] = Hash.new if @yaml[:desktop].nil?
 
       params[:desktop].each do |key, val|
@@ -294,6 +300,8 @@
   def drop_on_desktop
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     if @login_user.nil?
       t = Time.now
       render(:text => (t.hour.to_s + t.min.to_s + t.sec.to_s))
@@ -319,6 +327,8 @@
   def add_toy
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     if @login_user.nil?
       render(:text => '0')
       return
@@ -343,6 +353,9 @@
   def drop_on_recyclebox
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
+    SqlHelper.validate_token([params[:id]])
     unless @login_user.nil?
       Toy.destroy(params[:id])
     end
@@ -357,11 +370,14 @@
   #
   def on_toys_moved
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     unless @login_user.nil?
       begin
         toy = Toy.find(params[:id])
       rescue
+        toy = nil
       end
 
       unless toy.nil?
@@ -380,6 +396,8 @@
   #
   def create_label
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     if params[:thetisBoxEdit].empty?
       render(:partial => 'ajax_label', :layout => false)
@@ -411,6 +429,8 @@
   def update_label
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     msg = params[:thetisBoxEdit]
 
     if params[:thetisBoxEdit].empty?
@@ -455,6 +475,8 @@
   def post_label
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     if params[:txaPostLabel].empty? or params[:post_to].empty?
       render(:text => '')
       return
```
