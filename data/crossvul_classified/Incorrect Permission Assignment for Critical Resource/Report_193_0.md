# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in ruby
**Pair ID:** 193_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `193_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```ruby
Lines 98-139 of the vulnerable file.


    return unless self.target_package == '_product'

    Project.find_by_name!(self.target_project).update_product_autopackages
  end

  def check_action_permission!(skip_source = nil)
    super(skip_source)
    # only perform the following check, if we are called from
    # BsRequest.permission_check_change_state! (that is, if
    # skip_source is set to true). Always executing this check
    # would be a regression, because this code is also executed
    # if a new request is created (which could fail if User.current
    # cannot modify the source_package).
    return unless skip_source
    target_project = Project.get_by_name(self.target_project)
    return unless target_project && target_project.is_a?(Project)
    target_package = target_project.packages.find_by_name(self.target_package)
    initialize_devel_package = target_project.find_attribute('OBS', 'InitializeDevelPackage')
    return if target_package || !initialize_devel_package
    source_package = Package.get_by_project_and_name(source_project, self.source_package)
    return if !source_package || User.current.can_modify?(source_package)
    msg = 'No permission to initialize the source package as a devel package'
    raise PostRequestNoPermission, msg
  end

  #### Alias of methods
end

# == Schema Information
#
# Table name: bs_request_actions
#
#  id                    :integer          not null, primary key
#  bs_request_id         :integer          indexed, indexed => [target_package_id], indexed => [target_project_id]
#  type                  :string(255)
#  target_project        :string(255)      indexed
#  target_package        :string(255)      indexed
#  target_releaseproject :string(255)
#  source_project        :string(255)      indexed
#  source_package        :string(255)      indexed
#  source_rev            :string(255)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,8 +115,11 @@
     target_package = target_project.packages.find_by_name(self.target_package)
     initialize_devel_package = target_project.find_attribute('OBS', 'InitializeDevelPackage')
     return if target_package || !initialize_devel_package
-    source_package = Package.get_by_project_and_name(source_project, self.source_package)
-    return if !source_package || User.current.can_modify?(source_package)
+    opts = { follow_project_links: false }
+    source_package = Package.get_by_project_and_name!(source_project,
+                                                      self.source_package,
+                                                      opts)
+    return if User.current.can_modify?(source_package)
     msg = 'No permission to initialize the source package as a devel package'
     raise PostRequestNoPermission, msg
   end
```
