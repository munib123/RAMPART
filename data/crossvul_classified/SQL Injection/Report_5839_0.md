# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 5839_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5839_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 40-87 of the vulnerable file.

    current_user.pref[:activity_user] = params[:user] if params[:user]
    current_user.pref[:activity_duration] = params[:duration] if params[:duration]

    render :index
  end

  # GET /home/toggle                                                       AJAX
  #----------------------------------------------------------------------------
  def toggle
    if session[params[:id].to_sym]
      session.delete(params[:id].to_sym)
    else
      session[params[:id].to_sym] = true
    end
    render :nothing => true
  end

  # GET /home/timeline                                                     AJAX
  #----------------------------------------------------------------------------
  def timeline
    unless params[:type].empty?
      model = params[:type].camelize.constantize
      item = model.find(params[:id])
      item.update_attribute(:state, params[:state])
    else
      comments, emails = params[:id].split("+")
      Comment.update_all("state = '#{params[:state]}'", "id IN (#{comments})") unless comments.blank?
      Email.update_all("state = '#{params[:state]}'", "id IN (#{emails})") unless emails.blank?
    end

    render :nothing => true
  end

  # GET /home/timezone                                                     AJAX
  #----------------------------------------------------------------------------
  def timezone
    #
    # (new Date()).getTimezoneOffset() in JavaScript returns (UTC - localtime) in
    # minutes, while ActiveSupport::TimeZone expects (localtime - UTC) in seconds.
    #
    if params[:offset]
      session[:timezone_offset] = params[:offset].to_i * -60
      ActiveSupport::TimeZone[session[:timezone_offset]]
    end
    render :nothing => true
  end

  private
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,14 +57,19 @@
   # GET /home/timeline                                                     AJAX
   #----------------------------------------------------------------------------
   def timeline
-    unless params[:type].empty?
-      model = params[:type].camelize.constantize
-      item = model.find(params[:id])
-      item.update_attribute(:state, params[:state])
-    else
-      comments, emails = params[:id].split("+")
-      Comment.update_all("state = '#{params[:state]}'", "id IN (#{comments})") unless comments.blank?
-      Email.update_all("state = '#{params[:state]}'", "id IN (#{emails})") unless emails.blank?
+    state = params[:state].to_s
+    if %w(Collapsed Expanded).include?(state)
+      if (model_type = params[:type].to_s).present?
+        if %w(comment email).include?(model_type)
+          model = model_type.camelize.constantize
+          item = model.find(params[:id])
+          item.update_attribute(:state, state)
+        end
+      else
+        comments, emails = params[:id].split("+")
+        Comment.where(:id => comments.split(',')).update_all(:state => state) unless comments.blank?
+        Email.where(:id => emails.split(',')).update_all(:state => state) unless emails.blank?
+      end
     end
 
     render :nothing => true
```
