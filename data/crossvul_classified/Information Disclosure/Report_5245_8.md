# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_8
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_8`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-31 of the vulnerable file.

# Find known operating systems for associations
os_junos   = Operatingsystem.where(:type => "Junos") || Operatingsystem.where("name LIKE ?", "junos")
os_solaris = Operatingsystem.where(:type => "Solaris")
os_suse    = Operatingsystem.where(:type => "Suse") || Operatingsystem.where("name LIKE ?", "suse")
os_windows = Operatingsystem.where(:type => "Windows")

# Template kinds
kinds = {}
TemplateKind.default_template_labels.keys.collect(&:to_sym).each do |type|
  kinds[type] = TemplateKind.find_by_name(type)
  kinds[type] ||= TemplateKind.create(:name => type)
  raise "Unable to create template kind: #{format_errors kinds[type]}" if kinds[type].nil? || kinds[type].errors.any?
end

# Provisioning templates
organizations = Organization.all
locations = Location.all
ProvisioningTemplate.without_auditing do
  [
    # Generic PXE files
    { :name => 'PXELinux global default', :source => 'pxe/PXELinux_default.erb', :template_kind => kinds[:PXELinux], :locked => true },
    { :name => 'PXEGrub global default', :source => 'pxe/PXEGrub_default.erb', :template_kind => kinds[:PXEGrub], :locked => true },
    { :name => 'PXEGrub2 global default', :source => 'pxe/PXEGrub2_default.erb', :template_kind => kinds[:PXEGrub2], :locked => true },
    { :name => 'PXELinux default local boot', :source => 'pxe/PXELinux_local.erb', :template_kind => kinds[:PXELinux], :locked => true },
    { :name => 'PXEGrub default local boot', :source => 'pxe/PXEGrub_local.erb', :template_kind => kinds[:PXEGrub], :locked => true },
    { :name => 'PXEGrub2 default local boot', :source => 'pxe/PXEGrub2_local.erb', :template_kind => kinds[:PXEGrub2], :locked => true },
    { :name => 'PXELinux default memdisk', :source => 'pxe/PXELinux_memdisk.erb', :template_kind => kinds[:PXELinux] },
    { :name => 'PXELinux chain iPXE', :source => 'pxe/PXELinux_chain_iPXE.erb', :template_kind => kinds[:PXELinux] },
    { :name => 'PXELinux chain iPXE UNDI', :source => 'pxe/PXELinux_chain_iPXE_UNDI.erb', :template_kind => kinds[:PXELinux] },
    # OS specific files
    { :name => 'Alterator default', :source => 'alterator/provision.erb', :template_kind => kinds[:provision] },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,14 +7,14 @@
 # Template kinds
 kinds = {}
 TemplateKind.default_template_labels.keys.collect(&:to_sym).each do |type|
-  kinds[type] = TemplateKind.find_by_name(type)
-  kinds[type] ||= TemplateKind.create(:name => type)
+  kinds[type] = TemplateKind.unscoped.find_by_name(type)
+  kinds[type] ||= TemplateKind.unscoped.create(:name => type)
   raise "Unable to create template kind: #{format_errors kinds[type]}" if kinds[type].nil? || kinds[type].errors.any?
 end
 
 # Provisioning templates
-organizations = Organization.all
-locations = Location.all
+organizations = Organization.unscoped.all
+locations = Location.unscoped.all
 ProvisioningTemplate.without_auditing do
   [
     # Generic PXE files
@@ -81,7 +81,6 @@
     { :name => 'puppet.conf', :source => 'snippets/_puppet.conf.erb', :snippet => true },
     { :name => 'puppet_setup', :source => 'snippets/_puppet_setup.erb', :snippet => true },
     { :name => 'puppetlabs_repo', :source => 'snippets/_puppetlabs_repo.erb', :snippet => true },
-    { :name => 'pxelinux_discovery', :source => 'snippets/_pxelinux_discovery.erb', :snippet => true },
     { :name => 'redhat_register', :source => 'snippets/_redhat_register.erb', :snippet => true },
     { :name => 'remote_execution_ssh_keys', :source => 'snippets/_remote_execution_ssh_keys.erb', :snippet => true },
     { :name => 'saltstack_minion', :source => 'snippets/_saltstack_minion.erb', :snippet => true },
@@ -95,7 +94,7 @@
   ].each do |input|
     contents = File.read(File.join("#{Rails.root}/app/views/unattended", input.delete(:source)))
 
-    if (t = ProvisioningTemplate.find_by_name(input[:name])) && !audit_modified?(ProvisioningTemplate, input[:name])
+    if (t = ProvisioningTemplate.unscoped.find_by_name(input[:name])) && !audit_modified?(ProvisioningTemplate, input[:name])
       if t.template != contents
         t.template = contents
         raise "Unable to update template #{t.name}: #{format_errors t}" unless t.save
```
