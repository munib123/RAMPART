# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 74-114 of the vulnerable file.

  #
  def get_schedule
    Log.add_info(request, params.inspect)

    @date = Date.parse(params[:date])

    @schedules = Schedule.get_user_day(@login_user, @date)

    render(:partial => 'schedule', :layout => false)
  end

  #=== edit_timecard
  #
  #Shows the form to edit Timecard on Desktop.
  #
  def edit_timecard
    Log.add_info(request, params.inspect)

    date_s = params[:date]

    if date_s.nil? or date_s.empty?
      @date = Date.today
      date_s = @date.strftime(Schedule::SYS_DATE_FORM)
    else
      @date = Date.parse(date_s)
    end

    @timecard = Timecard.get_for(@login_user.id, date_s)

    render(:partial => 'timecard', :layout => false)
  end

  #=== edit_config
  #
  #Shows form of Desktop configuration.
  #
  def edit_config
    Log.add_info(request, params.inspect)

    if @login_user.admin?(User::AUTH_DESKTOP)
      @yaml = ApplicationHelper.get_config_yaml
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,7 +91,7 @@
 
     date_s = params[:date]
 
-    if date_s.nil? or date_s.empty?
+    if date_s.blank?
       @date = Date.today
       date_s = @date.strftime(Schedule::SYS_DATE_FORM)
     else
```
