# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 28-68 of the vulnerable file.

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
    SqlHelper.validate_token([@group_id])

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
          @group_id ||= target_location.group_id
        end
        break
      end
    end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,7 +45,7 @@
       con_second = []
       key_array = params[:keyword].split(nil)
       key_array.each do |key|
-        key_quot = ActiveRecord::Base.connection.quote(key)
+        key_quot = SqlHelper.quote(key)
         con_prim << "(name=#{key_quot} or fullname=#{key_quot} or email=#{key_quot})"
         con_second << SqlHelper.get_sql_like([:name, :fullname, :email], key)
       end
```
