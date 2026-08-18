# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 481-521 of the vulnerable file.

  #<Ajax>
  #Shows popup-window to select Users on Groups-Tree.
  #
  def select_users
    Log.add_info(request, params.inspect)

    render(:partial => 'select_users', :layout => false)
  end

  #=== get_group_users
  #
  #<Ajax>
  #Gets Users in specified Group.
  #
  def get_group_users
    Log.add_info(request, params.inspect)

    @group_id = nil
    if !params[:thetisBoxSelKeeper].nil?
      @group_id = params[:thetisBoxSelKeeper].split(':').last
    elsif !params[:group_id].nil? and !params[:group_id].empty?
      @group_id = params[:group_id]
    end

    submit_url = url_for(:controller => 'desktop', :action => 'get_group_users')
    render(:partial => 'common/select_users', :layout => false, :locals => {:target_attr => :id, :submit_url => submit_url})
  end

 private
  #=== check_toy_owner
  #
  #Filter method to check if current User is owner of the specified Toy.
  #
  def check_toy_owner
    return if params[:id].nil? or params[:id].empty? or @login_user.nil?

    begin
      owner_id = Toy.find(params[:id]).user_id
    rescue
      owner_id = -1
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -498,9 +498,10 @@
     @group_id = nil
     if !params[:thetisBoxSelKeeper].nil?
       @group_id = params[:thetisBoxSelKeeper].split(':').last
-    elsif !params[:group_id].nil? and !params[:group_id].empty?
+    elsif !params[:group_id].blank?
       @group_id = params[:group_id]
     end
+    SqlHelper.validate_token([@group_id])
 
     submit_url = url_for(:controller => 'desktop', :action => 'get_group_users')
     render(:partial => 'common/select_users', :layout => false, :locals => {:target_attr => :id, :submit_url => submit_url})
```
