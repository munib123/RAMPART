# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 646_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `646_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 81-121 of the vulnerable file.

    set_acceptinfo(result['acceptinfo'])

    target_package.sources_changed

    # cleanup source project
    if relink_source && !(sourceupdate == 'noupdate')
      # source package got used as devel package, link it to the target
      # re-create it via branch , but keep current content...
      options = { comment: "initialized devel package after accepting #{bs_request.number}",
        requestid: bs_request.number, keepcontent: 1, noservice: 1 }
      Backend::Api::Sources::Package.branch(self.target_project, self.target_package, source_project, source_package, User.current.login, options)
    elsif sourceupdate == 'cleanup'
      source_cleanup
    end

    return unless self.target_package == '_product'

    Project.find_by_name!(self.target_project).update_product_autopackages
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
#  sourceupdate          :string(255)
#  updatelink            :boolean          default(FALSE)
#  person_name           :string(255)
#  group_name            :string(255)
#  role                  :string(255)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,6 +98,26 @@
     Project.find_by_name!(self.target_project).update_product_autopackages
   end
 
+  def check_action_permission!(skip_source = nil)
+    super(skip_source)
+    # only perform the following check, if we are called from
+    # BsRequest.permission_check_change_state! (that is, if
+    # skip_source is set to true). Always executing this check
+    # would be a regression, because this code is also executed
+    # if a new request is created (which could fail if User.current
+    # cannot modify the source_package).
+    return unless skip_source
+    target_project = Project.get_by_name(self.target_project)
+    return unless target_project && target_project.is_a?(Project)
+    target_package = target_project.packages.find_by_name(self.target_package)
+    initialize_devel_package = target_project.find_attribute('OBS', 'InitializeDevelPackage')
+    return if target_package || !initialize_devel_package
+    source_package = Package.get_by_project_and_name(source_project, self.source_package)
+    return if !source_package || User.current.can_modify_package?(source_package)
+    msg = 'No permission to initialize the source package as a devel package'
+    raise PostRequestNoPermission, msg
+  end
+
   #### Alias of methods
 end
 
```
