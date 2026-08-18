# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_9
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_9`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-23 of the vulnerable file.

# Partition tables
organizations = Organization.all
locations = Location.all
Ptable.without_auditing do
  [
    { :name => 'AutoYaST entire SCSI disk', :os_family => 'Suse', :source => 'autoyast/disklayout_scsi.erb' },
    { :name => 'AutoYaST entire virtual disk', :os_family => 'Suse', :source => 'autoyast/disklayout_virtual.erb' },
    { :name => 'AutoYaST LVM', :os_family => 'Suse', :source => 'autoyast/disklayout_lvm.erb' },
    { :name => 'CoreOS default fake', :os_family => 'Coreos', :source => 'coreos/disklayout_CoreOS.erb' },
    { :name => 'FreeBSD', :os_family => 'Freebsd', :source => 'freebsd/disklayout_FreeBSD_mfsBSD.erb' },
    { :name => 'Jumpstart default', :os_family => 'Solaris', :source => 'jumpstart/disklayout.erb' },
    { :name => 'Jumpstart mirrored', :os_family => 'Solaris', :source => 'jumpstart/disklayout_mirrored.erb' },
    { :name => 'Junos default fake', :os_family => 'Junos', :source => 'ztp/disklayout.erb' },
    { :name => 'Kickstart default', :os_family => 'Redhat', :source => 'kickstart/disklayout.erb' },
    { :name => 'NX-OS default fake', :os_family => 'NXOS', :source => 'poap/disklayout.erb' },
    { :name => 'Preseed default', :os_family => 'Debian', :source => 'preseed/disklayout.erb' },
    { :name => 'Preseed custom LVM', :os_family => 'Debian', :source => 'preseed/disklayout_lvm.erb' },
    { :name => 'XenServer default', :os_family => 'Xenserver', :source => 'xenserver/disklayout.erb' }
  ].each do |input|
    contents = File.read(File.join("#{Rails.root}/app/views/unattended", input.delete(:source)))

    if (p = Ptable.find_by_name(input[:name])) && !audit_modified?(Ptable, input[:name])
      if p.layout != contents
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 # Partition tables
-organizations = Organization.all
-locations = Location.all
+organizations = Organization.unscoped.all
+locations = Location.unscoped.all
 Ptable.without_auditing do
   [
     { :name => 'AutoYaST entire SCSI disk', :os_family => 'Suse', :source => 'autoyast/disklayout_scsi.erb' },
@@ -19,7 +19,7 @@
   ].each do |input|
     contents = File.read(File.join("#{Rails.root}/app/views/unattended", input.delete(:source)))
 
-    if (p = Ptable.find_by_name(input[:name])) && !audit_modified?(Ptable, input[:name])
+    if (p = Ptable.unscoped.find_by_name(input[:name])) && !audit_modified?(Ptable, input[:name])
       if p.layout != contents
         p.layout = contents
         raise "Unable to update partition table: #{format_errors p}" unless p.save
```
