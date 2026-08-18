# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1555_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1555_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 246-286 of the vulnerable file.

  #Gets Users in the specified Group.
  #
  def get_users
    if params[:action] == 'get_users'
      Log.add_info(request, params.inspect)
    end

    @group_id = params[:id]

=begin
#    @users = Group.get_users(params[:id])
=end

# FEATURE_PAGING_IN_TREE >>>
    con = ['User.id > 0']

    unless @group_id.nil?
      if @group_id == '0'
        con << "((groups like '%|0|%') or (groups is null))"
      else
        con << ApplicationHelper.get_sql_like([:groups], "|#{@group_id}|")
      end
    end

    unless params[:keyword].blank?
      key_array = params[:keyword].split(nil)
      key_array.each do |key| 
        con << SqlHelper.get_sql_like([:name, :email, :fullname, :address, :organization, :tel1, :tel2, :tel3, :fax, :url, :postalcode, :title], key)
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -263,7 +263,7 @@
       if @group_id == '0'
         con << "((groups like '%|0|%') or (groups is null))"
       else
-        con << ApplicationHelper.get_sql_like([:groups], "|#{@group_id}|")
+        con << SqlHelper.get_sql_like([:groups], "|#{@group_id}|")
       end
     end
 
```
