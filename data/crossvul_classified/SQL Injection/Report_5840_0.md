# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 5840_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5840_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 105-145 of the vulnerable file.

  def activity_asset
    asset = current_user.pref[:activity_asset]
    if asset.nil? || asset == "all"
      nil
    else
      asset.singularize.capitalize
    end
  end

  #----------------------------------------------------------------------------
  def activity_event
    event = current_user.pref[:activity_event]
    if event == "all_events"
      %w(create update destroy)
    else
      event
    end
  end

  #----------------------------------------------------------------------------
  def activity_user
    user = current_user.pref[:activity_user]
    if user && user != "all_users"
      user = if user =~ /@/ # email
          User.where(:email => user).first
        else # first_name middle_name last_name any_name
          name_query = if user.include?(" ")
            user.name_permutations.map{ |first, last|
              "(upper(first_name) LIKE upper('%#{first}%') AND upper(last_name) LIKE upper('%#{last}%'))"
            }.join(" OR ")
          else
            "upper(first_name) LIKE upper('%#{user}%') OR upper(last_name) LIKE upper('%#{user}%')"
          end
          User.where(name_query).first
        end
    end
    user.is_a?(User) ? user.id : nil
  end

  #----------------------------------------------------------------------------
  def activity_duration
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,6 +122,9 @@
   end
 
   #----------------------------------------------------------------------------
+  # TODO: this is ugly, ugly code. It's being security patched now but urgently
+  # needs refactoring to use user id instead. Permuations based on name or email
+  # yield incorrect results.
   def activity_user
     user = current_user.pref[:activity_user]
     if user && user != "all_users"
@@ -130,12 +133,11 @@
         else # first_name middle_name last_name any_name
           name_query = if user.include?(" ")
             user.name_permutations.map{ |first, last|
-              "(upper(first_name) LIKE upper('%#{first}%') AND upper(last_name) LIKE upper('%#{last}%'))"
-            }.join(" OR ")
+              User.where(:first_name => first, :last_name => last)
+            }.map(&:to_a).flatten.first
           else
-            "upper(first_name) LIKE upper('%#{user}%') OR upper(last_name) LIKE upper('%#{user}%')"
+            [User.where(:first_name => user), User.where(:last_name => user)].map(&:to_a).flatten.first
           end
-          User.where(name_query).first
         end
     end
     user.is_a?(User) ? user.id : nil
```
