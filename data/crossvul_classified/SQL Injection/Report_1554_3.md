# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1554_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1554_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1-26 of the vulnerable file.

#
#= EquipmentController
#
#Original by::   Sysphonic
#Authors::   MORITA Shintaro
#Copyright:: Copyright (c) 2007-2011 MORITA Shintaro, Sysphonic. All rights reserved.
#License::   New BSD License (See LICENSE file)
#URL::   {http&#58;//sysphonic.com/}[http://sysphonic.com/]
#
#The Action-Controller about Equipment.
#
#== Note:
#
#* 
#
class EquipmentController < ApplicationController
  layout 'base'

  if $thetis_config[:menu]['req_login_equipment'] == '1'
    before_filter :check_login
  end

  before_filter :except => [:show, :list, :schedule_all] do |controller|
    controller.check_auth(User::AUTH_EQUIPMENT)
  end

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
@@ -41,6 +41,10 @@
   #
   def create
     Log.add_info(request, params.inspect)
+
+    return unless request.post?
+
+    SqlHelper.validate_token([params[:groups], params[:teams]])
 
     if params[:groups].blank?
       params[:equipment][:groups] = nil
@@ -101,15 +105,19 @@
   def update
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
+    SqlHelper.validate_token([params[:groups], params[:teams]])
+
     @equipment = Equipment.find(params[:id])
 
-    if (params[:groups].nil? or params[:groups].empty?)
+    if params[:groups].blank?
       params[:equipment][:groups] = nil
     else
       params[:equipment][:groups] = '|' + params[:groups].join('|') + '|'
     end
 
-    if (params[:teams].nil? or params[:teams].empty?)
+    if params[:teams].blank?
       params[:equipment][:teams] = nil
     else
       params[:equipment][:teams] = '|' + params[:teams].join('|') + '|'
@@ -178,6 +186,8 @@
   def destroy
     Log.add_info(request, params.inspect)
 
+    return unless request.post?
+
     if params[:check_equipment].nil?
       list
       render(:action => 'list')
@@ -186,6 +196,7 @@
 
     count = 0
     params[:check_equipment].each do |equipment_id, value|
+      SqlHelper.validate_token([equipment_id])
       if value == '1'
         Equipment.delete(equipment_id)
 
@@ -205,7 +216,7 @@
     Log.add_info(request, params.inspect)
 
     date_s = params[:date]
-    if date_s.nil? or date_s.empty?
+    if date_s.blank?
       @date = Date.today
     else
       @date = Date.parse(date_s)
```
