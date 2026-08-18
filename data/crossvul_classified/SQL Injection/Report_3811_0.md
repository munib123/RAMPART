# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 3811_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3811_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 34-74 of the vulnerable file.

        scoped_search :in => :organization, :on => :name, :rename => :organization, :complete_value => true if SETTINGS[:organizations_enabled]

        if SETTINGS[:unattended]
          scoped_search :in => :subnet,      :on => :network, :complete_value => true, :rename => :subnet
          scoped_search :on => :mac,           :complete_value => true
          scoped_search :on => :uuid,          :complete_value => true
          scoped_search :on => :build,         :complete_value => {:true => true, :false => false}
          scoped_search :on => :installed_at,  :complete_value => true
          scoped_search :in => :operatingsystem, :on => :name, :complete_value => true, :rename => :os
        end

        if SETTINGS[:login]
          scoped_search :in => :search_users, :on => :login,     :complete_value => true, :only_explicit => true, :rename => :'user.login',    :operators => ['= ', '~ '], :ext_method => :search_by_user
          scoped_search :in => :search_users, :on => :firstname, :complete_value => true, :only_explicit => true, :rename => :'user.firstname',:operators => ['= ', '~ '], :ext_method => :search_by_user
          scoped_search :in => :search_users, :on => :lastname,  :complete_value => true, :only_explicit => true, :rename => :'user.lastname', :operators => ['= ', '~ '], :ext_method => :search_by_user
          scoped_search :in => :search_users, :on => :mail,      :complete_value => true, :only_explicit => true, :rename => :'user.mail',     :operators => ['= ', '~ '], :ext_method => :search_by_user
        end

        def self.search_by_user(key, operator, value)
          key_name = key.sub(/^.*\./,'')
          users = User.all(:conditions => "#{key_name} #{operator} '#{value_to_sql(operator, value)}'")
          hosts = users.map(&:hosts).flatten
          opts  = hosts.empty? ? "= 'nil'" : "IN (#{hosts.map(&:id).join(',')})"

          return {:conditions => " hosts.id #{opts} " }
        end

        def self.search_by_puppetclass(key, operator, value)
          conditions  = "puppetclasses.name #{operator} '#{value_to_sql(operator, value)}'"
          hosts       = Host.my_hosts.all(:conditions => conditions, :joins => :puppetclasses, :select => 'DISTINCT hosts.id').map(&:id)
          host_groups = Hostgroup.all(:conditions => conditions, :joins => :puppetclasses, :select => 'DISTINCT hostgroups.id').map(&:id)

          opts = ''
          opts += "hosts.id IN(#{hosts.join(',')})"             unless hosts.blank?
          opts += " OR "                                        unless hosts.blank? || host_groups.blank?
          opts += "hostgroups.id IN(#{host_groups.join(',')})"  unless host_groups.blank?
          opts = "hosts.id < 0"                                 if hosts.blank? && host_groups.blank?
          return {:conditions => opts, :include => :hostgroup}
        end

        def self.search_by_params(key, operator, value)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,15 +51,16 @@
 
         def self.search_by_user(key, operator, value)
           key_name = key.sub(/^.*\./,'')
-          users = User.all(:conditions => "#{key_name} #{operator} '#{value_to_sql(operator, value)}'")
+          condition = sanitize_sql_for_conditions(["? #{operator} ?", key_name, value_to_sql(operator, value)])
+          users = User.all(:conditions => condition)
           hosts = users.map(&:hosts).flatten
-          opts  = hosts.empty? ? "= 'nil'" : "IN (#{hosts.map(&:id).join(',')})"
+          opts  = hosts.empty? ? "< 0" : "IN (#{hosts.map(&:id).join(',')})"
 
           return {:conditions => " hosts.id #{opts} " }
         end
 
         def self.search_by_puppetclass(key, operator, value)
-          conditions  = "puppetclasses.name #{operator} '#{value_to_sql(operator, value)}'"
+          conditions  = sanitize_sql_for_conditions(["puppetclasses.name #{operator} ?", value_to_sql(operator, value)])
           hosts       = Host.my_hosts.all(:conditions => conditions, :joins => :puppetclasses, :select => 'DISTINCT hosts.id').map(&:id)
           host_groups = Hostgroup.all(:conditions => conditions, :joins => :puppetclasses, :select => 'DISTINCT hostgroups.id').map(&:id)
 
@@ -73,12 +74,14 @@
 
         def self.search_by_params(key, operator, value)
           key_name = key.sub(/^.*\./,'')
-          opts     = {:conditions => "name = '#{key_name}' and value #{operator} '#{value_to_sql(operator, value)}'", :order => :priority}
+          condition = sanitize_sql_for_conditions(["name = ? and value #{operator} ?", key_name, value_to_sql(operator, value)])
+          opts     = {:conditions => condition, :order => :priority}
           p        = Parameter.all(opts)
           return {:conditions => '1 = 0'} if p.blank?
 
           max         = p.first.priority
-          negate_opts = {:conditions => "name = '#{key_name}' and NOT(value #{operator} '#{value_to_sql(operator, value)}') and priority > #{max}", :order => :priority}
+          condition   = sanitize_sql_for_conditions(["name = ? and NOT(value #{operator} ?) and priority > ?",key_name,value_to_sql(operator, value), max])
+          negate_opts = {:conditions => condition, :order => :priority}
           n           = Parameter.all(negate_opts)
 
           conditions = param_conditions(p)
```
