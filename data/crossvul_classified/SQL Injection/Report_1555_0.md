# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1555_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1555_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 126-166 of the vulnerable file.


  #=== list
  #
  #Shows Equipment list.
  #
  def list
    Log.add_info(request, params.inspect)

    con = []

    @group_id = nil
    if !params[:thetisBoxSelKeeper].nil?
      @group_id = params[:thetisBoxSelKeeper].split(':').last
    elsif !params[:group_id].blank?
      @group_id = params[:group_id]
    end
    unless @group_id.nil?
      if @group_id == '0'
        con << "((groups like '%|0|%') or (groups is null))"
      else
        con << ApplicationHelper.get_sql_like([:groups], "|#{@group_id}|")
      end
    end

    where = ''
    unless con.empty?
      where = ' where ' + con.join(' and ')
    end

    order_by = nil
    @sort_col = params[:sort_col]
    @sort_type = params[:sort_type]

    if @sort_col.blank? or @sort_type.blank?
      @sort_col = 'id'
      @sort_type = 'ASC'
    end
    SqlHelper.validate_token([@sort_col, @sort_type])
    order_by = ' order by ' + @sort_col + ' ' + @sort_type

    sql = 'select distinct Equipment.* from equipment Equipment'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,7 +143,7 @@
       if @group_id == '0'
         con << "((groups like '%|0|%') or (groups is null))"
       else
-        con << ApplicationHelper.get_sql_like([:groups], "|#{@group_id}|")
+        con << SqlHelper.get_sql_like([:groups], "|#{@group_id}|")
       end
     end
 
@@ -219,11 +219,11 @@
       case display_type
        when 'group'
         if @login_user.get_groups_a(true).include?(display_id)
-          con = ApplicationHelper.get_sql_like([:groups], "|#{display_id}|")
+          con = SqlHelper.get_sql_like([:groups], "|#{display_id}|")
         end
        when 'team'
         if @login_user.get_teams_a.include?(display_id)
-          con = ApplicationHelper.get_sql_like([:teams], "|#{display_id}|")
+          con = SqlHelper.get_sql_like([:teams], "|#{display_id}|")
         end
       end
     end
```
