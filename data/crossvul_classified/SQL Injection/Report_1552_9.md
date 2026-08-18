# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_9
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 410-450 of the vulnerable file.

  #
  def users
    if params[:action] == 'users'
      Log.add_info(request, params.inspect)
    end

    con = ['User.id > 0']
    unless params[:keyword].blank?
      key_array = params[:keyword].split(nil)
      key_array.each do |key| 
        con << SqlHelper.get_sql_like([:name, :email, :fullname, :address, :organization, :tel1, :tel2, :tel3, :fax, :url, :postalcode, :title], key)
      end
    end

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
        con << SqlHelper.get_sql_like([:groups], "|#{@group_id}|")
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
      @sort_col = "xorder"
      @sort_type = "ASC"
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -427,6 +427,8 @@
     elsif !params[:group_id].blank?
       @group_id = params[:group_id]
     end
+    SqlHelper.validate_token([@group_id])
+
     unless @group_id.nil?
       if @group_id == '0'
         con << "((groups like '%|0|%') or (groups is null))"
```
