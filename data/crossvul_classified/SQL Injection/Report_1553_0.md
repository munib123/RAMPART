# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 58-98 of the vulnerable file.

  #_options_:: Same as the corresponding argument of the super method.
  #_&blk_:: Same as the corresponding argument of the super method.
  #
  def render(action=nil, options={}, &blk)
    opts = options
    if opts.empty? and !action.nil? and action.kind_of?(Hash)
      opts = action
    end
    unless opts.nil?
      if opts[:layout] == false
        opts[:layout] = 'layouts/xhr'
      end
    end
    super(action, options, &blk)
  end

 public
  #=== paginate_by_sql
  #
  def paginate_by_sql(model, sql, per_page, options={})
    if options[:count]
      if options[:count].is_a?(Integer)
        total = options[:count]
      else
        total = model.count_by_sql(options[:count])
      end
    else
      total = model.count_by_sql_wrapping_select_query(sql)
    end

    object_pages = model.paginate_by_sql(sql, {:page => params['page'], :per_page => per_page})
    #objects = model.find_by_sql_with_limit(sql, object_pages.current.to_sql[1], per_page)
    return [object_pages, object_pages, total]
  end

 protected
  #=== gate_process
  #
  #Does processes requiered for each access.
  #
  def gate_process
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,18 +75,18 @@
   #=== paginate_by_sql
   #
   def paginate_by_sql(model, sql, per_page, options={})
-    if options[:count]
+    if options[:count].blank?
+      total = model.count_by_sql_wrapping_select_query(sql)
+    else
       if options[:count].is_a?(Integer)
         total = options[:count]
-      else
-        total = model.count_by_sql(options[:count])
+      #else
+      #  total = model.count_by_sql(options[:count])
       end
-    else
-      total = model.count_by_sql_wrapping_select_query(sql)
     end
 
+    SqlHelper.validate_token([params['page']])
     object_pages = model.paginate_by_sql(sql, {:page => params['page'], :per_page => per_page})
-    #objects = model.find_by_sql_with_limit(sql, object_pages.current.to_sql[1], per_page)
     return [object_pages, object_pages, total]
   end
 
@@ -99,7 +99,7 @@
 
     HistoryHelper.keep_last(request)
 
-    @login_user = User.find_by_id(session[:login_user_id])
+    @login_user = User.find(session[:login_user_id])
 
     begin
       if @login_user.nil? \
@@ -118,12 +118,6 @@
 
 module ActiveRecord
   class Base
-    def self.find_by_sql_with_limit(sql, offset, limit)
-      sql = sanitize_sql(sql)
-      add_limit!(sql, {:limit => limit, :offset => offset})
-      find_by_sql(sql)
-    end
-
     def self.count_by_sql_wrapping_select_query(sql)
       sql = sanitize_sql(sql)
       count_by_sql("select count(*) from (#{sql}) as my_table")
```
