# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1558_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1558_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 82-122 of the vulnerable file.

        total = options[:count]
      #else
      #  total = model.count_by_sql(options[:count])
      end
    end

    SqlHelper.validate_token([params['page']])
    object_pages = model.paginate_by_sql(sql, {:page => params['page'], :per_page => per_page})
    return [object_pages, object_pages, total]
  end

 protected
  #=== gate_process
  #
  #Does processes requiered for each access.
  #
  def gate_process

    HistoryHelper.keep_last(request)

    @login_user = User.find(session[:login_user_id])

    begin
      if @login_user.nil? \
           or @login_user.time_zone.nil? or @login_user.time_zone.empty?
        unless THETIS_USER_TIMEZONE_DEFAULT.nil? or THETIS_USER_TIMEZONE_DEFAULT.empty?
          Time.zone = THETIS_USER_TIMEZONE_DEFAULT
        end
      else
        Time.zone = @login_user.time_zone
      end
    rescue => evar
      logger.fatal(evar.to_s)
    end
  end
end

module ActiveRecord
  class Base
    def self.count_by_sql_wrapping_select_query(sql)
      sql = sanitize_sql(sql)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,12 @@
 
     HistoryHelper.keep_last(request)
 
-    @login_user = User.find(session[:login_user_id])
+    SqlHelper.validate_token([session[:login_user_id]])
+    begin
+      @login_user = User.find(session[:login_user_id])
+    rescue => evar
+      @login_user = nil
+    end
 
     begin
       if @login_user.nil? \
```
