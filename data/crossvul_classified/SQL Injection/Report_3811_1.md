# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 3811_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3811_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 134-172 of the vulnerable file.

    prepare_script = Pathname.new(Rails.root) + "script/rdoc_prepare_script.rb"
    if prepare_script.executable?
      dirs = Environment.puppetEnvs.values.join(":").split(":").uniq.sort.join(" ")
      puts "Running #{prepare_script} #{dirs}" if debug
      location = %x{#{prepare_script} #{dirs}}
      if $? == 0
        root = location.chomp
        puts "Relocated modules to #{root}" if verbose
      end
    else
      puts "No executable #{prepare_script} found so using the uncopied module sources" if verbose
    end
    root
  end

  def as_json(options={})
    super({:only => [:name, :id], :include => [:lookup_keys]})
  end

  def self.search_by_host(key, operator, value)
    conditions = "hosts.name #{operator} '#{value_to_sql(operator, value)}'"
    direct     = Puppetclass.all(:conditions => conditions, :joins => :hosts, :select => 'puppetclasses.id').map(&:id).uniq
    hostgroup  = Hostgroup.joins(:hosts).where(conditions).first
    indirect   = HostgroupClass.where(:hostgroup_id => hostgroup.path_ids).pluck(:puppetclass_id).uniq
    return { :conditions => "1=0" } if direct.blank? && indirect.blank?

    puppet_classes = (direct + indirect).uniq
    { :conditions => "puppetclasses.id IN(#{puppet_classes.join(',')})" }
  end


  def self.value_to_sql(operator, value)
    return value                 if operator !~ /LIKE/i
    return value.tr_s('%*', '%') if (value ~ /%|\*/)

    return "%#{value}%"
  end

end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -151,8 +151,8 @@
   end
 
   def self.search_by_host(key, operator, value)
-    conditions = "hosts.name #{operator} '#{value_to_sql(operator, value)}'"
-    direct     = Puppetclass.all(:conditions => conditions, :joins => :hosts, :select => 'puppetclasses.id').map(&:id).uniq
+    conditions = sanitize_sql_for_conditions(["hosts.name #{operator} ?", value_to_sql(operator, value)])
+    direct     = Puppetclass.joins(:hosts).where(conditions).select('puppetclasses.id').map(&:id).uniq
     hostgroup  = Hostgroup.joins(:hosts).where(conditions).first
     indirect   = HostgroupClass.where(:hostgroup_id => hostgroup.path_ids).pluck(:puppetclass_id).uniq
     return { :conditions => "1=0" } if direct.blank? && indirect.blank?
```
