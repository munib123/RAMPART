# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1557_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1557_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 1255-1295 of the vulnerable file.

  #<Ajax>
  #Organizes Team.
  #
  def team_organize
    Log.add_info(request, params.inspect)

    team_id = params[:team_id]
    unless team_id.blank?
      begin
        @team = Team.find(team_id)
      rescue
        @team = nil
      ensure
        if @team.nil?
          flash[:notice] = t('msg.already_deleted', :name => Team.model_name.human)
          return
        end
      end

      users = @team.get_users_a
    end 

    team_members = params[:team_members]

    created = false
    modified = false

    if team_members.nil? or team_members.empty?

      unless team_id.blank?
        # @team must not be nil.
        @team.save if modified = @team.clear_users
      end

    else

      if team_members != users

        if team_id.blank?

          item = Item.find(params[:id])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1272,9 +1272,10 @@
       end
 
       users = @team.get_users_a
-    end 
+    end
 
     team_members = params[:team_members]
+    SqlHelper.validate_token([team_members])
 
     created = false
     modified = false
@@ -1305,9 +1306,9 @@
           @team.clear_users
         end
 
-        @team.add_users team_members
+        @team.add_users(team_members)
         @team.save
-        @team.remove_application team_members
+        @team.remove_application(team_members)
 
         modified = true 
       end
```
