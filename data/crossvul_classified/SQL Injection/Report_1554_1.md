# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1554_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1554_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1-26 of the vulnerable file.

#
#= ConfigController
#
#Original by::   Sysphonic
#Authors::   MORITA Shintaro
#Copyright:: Copyright (c) 2007-2011 MORITA Shintaro, Sysphonic. All rights reserved.
#License::   New BSD License (See LICENSE file)
#URL::   {http&#58;//sysphonic.com/}[http://sysphonic.com/]
#
#The Action-Controller about Configuration of Thetis.
#
#== Note:
#
#*
#
class ConfigController < ApplicationController
  layout 'base'

  before_filter :check_login
  before_filter :except => [:update_by_ajax] do |controller|
    controller.check_auth(User::AUTH_ALL)
  end


  #=== edit
  #
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
@@ -39,13 +39,15 @@
   def update_by_ajax
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     cat_h = {:desktop => User::AUTH_DESKTOP, :user => User::AUTH_USER, :log => User::AUTH_LOG}
 
     yaml = ApplicationHelper.get_config_yaml
 
     cat_h.keys.each do |cat|
 
-      next if params[cat].nil? or params[cat].empty?
+      next if params[cat].blank?
 
       unless @login_user.admin?(cat_h[cat])
         render(:text => t('msg.need_to_be_admin'))
@@ -70,6 +72,8 @@
   #
   def update
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     categories = [:general, :menu, :topic, :note, :smtp, :feed, :user, :log]
 
@@ -149,6 +153,8 @@
   def destroy_header_menu
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     @yaml = ApplicationHelper.get_config_yaml
 
     unless params[:org_name].nil? or @yaml[:general]['header_menus'].nil?
@@ -171,6 +177,8 @@
   #
   def update_header_menu
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
 
     @yaml = ApplicationHelper.get_config_yaml
 
@@ -221,6 +229,8 @@
   def update_header_menus_order
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     header_menus = params[:header_menus_order]
 
     yaml = ApplicationHelper.get_config_yaml
```
