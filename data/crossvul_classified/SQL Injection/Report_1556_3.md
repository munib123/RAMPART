# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1556_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1556_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 517-557 of the vulnerable file.

      if !yaml[:timecard].nil? and yaml[:timecard]['always_by_full_name'] == '1'
        return self.fullname
      else
        return self.name
      end
    end
  end

  #=== self.get_from_name
  #
  #Gets User who has specified name.
  #
  #_user_name_:: Target User name
  #return:: User.
  #
  def self.get_from_name(user_name)

    SqlHelper.validate_token([user_name])

    begin
      user = User.where("name='#{user_name}'").first
    rescue => evar
      Log.add_error(nil, evar)
    end

    return user
  end

  #=== get_groups_a
  #
  #Gets Groups array to which this User belongs.
  #
  #_incl_parents_:: Flag to require parent Group-IDS by return.
  #_group_obj_cache_:: Hash to accelerate response. {group_id, group}
  #return:: Array of Group-IDs.
  #
  def get_groups_a(incl_parents=false, group_obj_cache=nil)

    return ['0'] if self.groups.nil? or self.groups.empty?

    arr = self.groups.split('|')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -534,7 +534,7 @@
     SqlHelper.validate_token([user_name])
 
     begin
-      user = User.where("name='#{user_name}'").first
+      user = User.where(name: user_name).first
     rescue => evar
       Log.add_error(nil, evar)
     end
```
