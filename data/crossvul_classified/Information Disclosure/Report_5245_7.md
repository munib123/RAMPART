# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 20-60 of the vulnerable file.

    execute "DELETE FROM user_compute_resources WHERE compute_resource_id NOT IN (SELECT id FROM compute_resources) OR user_id NOT IN (SELECT id FROM users)"
    execute "DELETE FROM user_domains WHERE domain_id NOT IN (SELECT id FROM domains) OR user_id NOT IN (SELECT id FROM users)"
    execute "DELETE FROM user_facts WHERE fact_name_id NOT IN (SELECT id FROM fact_names) OR user_id NOT IN (SELECT id FROM users)"
    execute "DELETE FROM user_hostgroups WHERE hostgroup_id NOT IN (SELECT id FROM hostgroups) OR user_id NOT IN (SELECT id FROM users)"
    execute "DELETE FROM user_roles WHERE role_id NOT IN (SELECT id FROM roles) OR user_id NOT IN (SELECT id FROM users)"
    KeyPair.where("compute_resource_id NOT IN (?)", ComputeResource.pluck(:id)).delete_all
    LookupKey.where("puppetclass_id NOT IN (?)", Puppetclass.pluck(:id)).delete_all
    execute "DELETE FROM environment_classes WHERE environment_id NOT IN (SELECT id FROM environments) OR lookup_key_id NOT IN (SELECT id FROM lookup_keys) OR puppetclass_id NOT IN (SELECT id FROM puppetclasses)"
    LookupValue.where("lookup_key_id NOT IN (?)", LookupKey.pluck(:id)).delete_all
    FactValue.where("fact_name_id NOT IN (?) OR host_id NOT IN (?)", FactName.pluck(:id), Host::Base.pluck(:id)).delete_all
    TaxableTaxonomy.where("taxonomy_id NOT IN (?)", Taxonomy.unscoped.pluck(:id)).delete_all
    HostClass.where("host_id NOT IN (?) OR puppetclass_id NOT IN (?)", Host::Base.pluck(:id), Puppetclass.pluck(:id)).delete_all
    # .unscoped is needed since the default scope orders by title, but title is not a db field yet.
    HostgroupClass.where("hostgroup_id NOT IN (?) OR puppetclass_id NOT IN (?)", Hostgroup.unscoped.pluck(:id), Puppetclass.pluck(:id)).delete_all
    Report.where("host_id NOT IN (?)", Host::Base.pluck(:id)).delete_all
    Log.where("message_id NOT IN (?) OR report_id NOT IN (?) OR source_id NOT IN (?)", Message.pluck(:id), Report.pluck(:id), Source.pluck(:id)).delete_all
    Token.where("host_id NOT IN (?)", Host::Base.pluck(:id)).delete_all
    TrendCounter.where("trend_id NOT IN (?)", Trend.pluck(:id)).delete_all

    # NULLIFY FOREIGN KEY VALUE IF IT HAS AN ORPHANED FOREIGN KEY
    Audit.unscoped.where("user_id NOT IN (?)", User.pluck(:id)).update_all(:user_id => nil)
    FakeConfigTemplate.where("template_kind_id NOT IN (?)", TemplateKind.pluck(:id)).update_all(:template_kind_id => nil)
    Domain.where("dns_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:dns_id => nil)
    Subnet.where("dhcp_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:dhcp_id => nil)
    Subnet.where("dns_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:dns_id => nil)
    Subnet.where("tftp_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:tftp_id => nil)
    Image.where("architecture_id NOT IN (?)", Architecture.pluck(:id)).update_all(:architecture_id => nil)
    Image.where("compute_resource_id NOT IN (?)", ComputeResource.pluck(:id)).update_all(:compute_resource_id => nil)
    Image.where("operatingsystem_id NOT IN (?)", Operatingsystem.unscoped.pluck(:id)).update_all(:operatingsystem_id => nil)
    Nic::Base.where("domain_id NOT IN (?)", Domain.pluck(:id)).update_all(:domain_id => nil)
    Nic::Base.where("host_id NOT IN (?)", Host::Base.pluck(:id)).update_all(:host_id => nil)
    Nic::Base.where("subnet_id NOT IN (?)", Subnet.pluck(:id)).update_all(:subnet_id => nil)
    OsDefaultTemplate.where("config_template_id NOT IN (?)", FakeConfigTemplate.pluck(:id)).update_all(:config_template_id => nil)
    OsDefaultTemplate.where("operatingsystem_id NOT IN (?)", Operatingsystem.unscoped.pluck(:id)).update_all(:operatingsystem_id => nil)
    OsDefaultTemplate.where("template_kind_id NOT IN (?)", TemplateKind.pluck(:id)).update_all(:template_kind_id => nil)
    TemplateCombination.where("config_template_id NOT IN (?)", FakeConfigTemplate.pluck(:id)).update_all(:config_template_id => nil)
... (excerpt truncated)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,23 +37,23 @@
     TrendCounter.where("trend_id NOT IN (?)", Trend.pluck(:id)).delete_all
 
     # NULLIFY FOREIGN KEY VALUE IF IT HAS AN ORPHANED FOREIGN KEY
-    Audit.unscoped.where("user_id NOT IN (?)", User.pluck(:id)).update_all(:user_id => nil)
+    Audit.unscoped.where("user_id NOT IN (?)", User.unscoped.pluck(:id)).update_all(:user_id => nil)
     FakeConfigTemplate.where("template_kind_id NOT IN (?)", TemplateKind.pluck(:id)).update_all(:template_kind_id => nil)
-    Domain.where("dns_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:dns_id => nil)
-    Subnet.where("dhcp_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:dhcp_id => nil)
-    Subnet.where("dns_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:dns_id => nil)
-    Subnet.where("tftp_id NOT IN (?)", SmartProxy.pluck(:id)).update_all(:tftp_id => nil)
-    Image.where("architecture_id NOT IN (?)", Architecture.pluck(:id)).update_all(:architecture_id => nil)
-    Image.where("compute_resource_id NOT IN (?)", ComputeResource.pluck(:id)).update_all(:compute_resource_id => nil)
+    Domain.where("dns_id NOT IN (?)", SmartProxy.unscoped.pluck(:id)).update_all(:dns_id => nil)
+    Subnet.where("dhcp_id NOT IN (?)", SmartProxy.unscoped.pluck(:id)).update_all(:dhcp_id => nil)
+    Subnet.where("dns_id NOT IN (?)", SmartProxy.unscoped.pluck(:id)).update_all(:dns_id => nil)
+    Subnet.where("tftp_id NOT IN (?)", SmartProxy.unscoped.pluck(:id)).update_all(:tftp_id => nil)
+    Image.where("architecture_id NOT IN (?)", Architecture.unscoped.pluck(:id)).update_all(:architecture_id => nil)
+    Image.where("compute_resource_id NOT IN (?)", ComputeResource.unscoped.pluck(:id)).update_all(:compute_resource_id => nil)
     Image.where("operatingsystem_id NOT IN (?)", Operatingsystem.unscoped.pluck(:id)).update_all(:operatingsystem_id => nil)
-    Nic::Base.where("domain_id NOT IN (?)", Domain.pluck(:id)).update_all(:domain_id => nil)
-    Nic::Base.where("host_id NOT IN (?)", Host::Base.pluck(:id)).update_all(:host_id => nil)
-    Nic::Base.where("subnet_id NOT IN (?)", Subnet.pluck(:id)).update_all(:subnet_id => nil)
-    OsDefaultTemplate.where("config_template_id NOT IN (?)", FakeConfigTemplate.pluck(:id)).update_all(:config_template_id => nil)
+    Nic::Base.where("domain_id NOT IN (?)", Domain.unscoped.pluck(:id)).update_all(:domain_id => nil)
+    Nic::Base.where("host_id NOT IN (?)", Host::Base.unscoped.pluck(:id)).update_all(:host_id => nil)
+    Nic::Base.where("subnet_id NOT IN (?)", Subnet.unscoped.pluck(:id)).update_all(:subnet_id => nil)
+    OsDefaultTemplate.where("config_template_id NOT IN (?)", FakeConfigTemplate.unscoped.pluck(:id)).update_all(:config_template_id => nil)
     OsDefaultTemplate.where("operatingsystem_id NOT IN (?)", Operatingsystem.unscoped.pluck(:id)).update_all(:operatingsystem_id => nil)
-    OsDefaultTemplate.where("template_kind_id NOT IN (?)", TemplateKind.pluck(:id)).update_all(:template_kind_id => nil)
-    TemplateCombination.where("config_template_id NOT IN (?)", FakeConfigTemplate.pluck(:id)).update_all(:config_template_id => nil)
-    TemplateCombination.where("environment_id NOT IN (?)", Environment.pluck(:id)).update_all(:environment_id => nil)
+    OsDefaultTemplate.where("template_kind_id NOT IN (?)", TemplateKind.unscoped.pluck(:id)).update_all(:template_kind_id => nil)
+    TemplateCombination.where("config_template_id NOT IN (?)", FakeConfigTemplate.unscoped.pluck(:id)).update_all(:config_template_id => nil)
+    TemplateCombination.where("environment_id NOT IN (?)", Environment.unscoped.pluck(:id)).update_all(:environment_id => nil)
     TemplateCombination.where("hostgroup_id NOT IN (?)", Hostgroup.unscoped.pluck(:id)).update_all(:hostgroup_id => nil)
 
     host_groups_up
```
