# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 21-61 of the vulnerable file.


  before_filter :only => [:update_map, :delete_map] do |controller|
    controller.check_auth(User::AUTH_LOCATION)
  end


  #=== open_map
  #
  #Gets Locations of Users.
  #
  def open_map
    Log.add_info(request, params.inspect)

    @group_id = nil

    if !params[:thetisBoxSelKeeper].nil?
      @group_id = params[:thetisBoxSelKeeper].split(':').last
    elsif !params[:group_id].blank?
      @group_id = params[:group_id]
    end

    unless params[:keyword].blank?
      con_prim = []
      con_second = []
      key_array = params[:keyword].split(nil)
      key_array.each do |key|
        key_quot = ActiveRecord::Base.connection.quote(key)
        con_prim << "(name=#{key_quot} or fullname=#{key_quot} or email=#{key_quot})"
        con_second << SqlHelper.get_sql_like([:name, :fullname, :email], key)
      end
      [con_prim, con_second].each do |con|
        next if con.empty?

        begin
          @target_user = User.where(con.join(' and ')).first
        rescue
        end
        next if @target_user.nil?

        target_location = Location.get_for(@target_user)
        unless target_location.nil?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,7 @@
     elsif !params[:group_id].blank?
       @group_id = params[:group_id]
     end
+    SqlHelper.validate_token([@group_id])
 
     unless params[:keyword].blank?
       con_prim = []
@@ -142,6 +143,7 @@
     Log.add_info(request, params.inspect)
 
     group_id = params[:group_id]
+    SqlHelper.validate_token([group_id])
 
     @office_map = OfficeMap.get_for_group(group_id, true)
 
@@ -163,6 +165,7 @@
     Log.add_info(request, params.inspect)
 
     group_id = params[:group_id]
+    SqlHelper.validate_token([group_id])
 
     @office_map = OfficeMap.get_for_group(group_id, false)
 
```
