# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 103-143 of the vulnerable file.

    unless params[:user_id].nil?
      if params[:user_id] != @login_user.id.to_s and !@login_user.admin?(User::AUTH_TIMECARD)
        Log.add_check(request, '[User::AUTH_TIMECARD]'+request.to_s)
        render(:text => 'ERROR:' + t('msg.need_auth_to_access'))
        return
      end
    end

    month
  end

  #=== edit
  #
  #Shows the form to edit Timecard.
  #
  def edit
    Log.add_info(request, params.inspect)

    date_s = params[:date]

    if date_s.nil? or date_s.empty?
      @date = Date.today
      date_s = @date.strftime(Schedule::SYS_DATE_FORM)
    else
      @date = Date.parse(date_s)
    end

    if params[:user_id].nil?
      @selected_user = @login_user
    else
      @selected_user = User.find(params[:user_id])
    end

    @timecard = Timecard.get_for(@selected_user.id, date_s)

    if @selected_user == @login_user
      @schedules = Schedule.get_user_day(@login_user, @date)
    end

    if !params[:display].nil? and params[:display].split('_').first == 'group'
      @group_id = params[:display].split('_').last
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,7 +120,7 @@
 
     date_s = params[:date]
 
-    if date_s.nil? or date_s.empty?
+    if date_s.blank?
       @date = Date.today
       date_s = @date.strftime(Schedule::SYS_DATE_FORM)
     else
```
