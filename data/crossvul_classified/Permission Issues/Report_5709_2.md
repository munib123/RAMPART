# CrossVul Fix Pair: Permission Issues in ruby
**Pair ID:** 5709_2
**Vulnerability Class:** Permission Issues
**CWE:** CWE-275
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5709_2`)

## Vulnerability Information & PoC

## Description
Permission Issues

## Vulnerable Code
```ruby
Lines 1-41 of the vulnerable file.

require 'opensuse/backend'

class Project < ActiveRecord::Base
  include FlagHelper

  class CycleError < APIException
    setup "project_cycle"
  end
  class DeleteError < APIException
    setup "delete_error"
  end
  # unknown objects and no read access permission are handled in the same way by default
  class ReadAccessError < APIException
    setup 'unknown_project', 404, "Unknown project"
  end
  class UnknownObjectError < APIException
    setup 'unknown_project', 404, "Unknown project"
  end
  class SaveError < APIException
    setup "project_save_error"
  end
  class ForbiddenError < APIException
    setup("change_project_protection_level", 403,
          "admin rights are required to raise the protection level of a project (it won't be safe anyway)")
  end

  before_destroy :cleanup_before_destroy
  after_save 'ProjectUserRoleRelationship.discard_cache'
  after_rollback :reset_cache
  after_rollback 'ProjectUserRoleRelationship.discard_cache'

  has_many :project_user_role_relationships, :dependent => :delete_all, foreign_key: :db_project_id
  has_many :project_group_role_relationships, :dependent => :delete_all, foreign_key: :db_project_id

  has_many :packages, :dependent => :destroy, foreign_key: :db_project_id
  has_many :attribs, :dependent => :destroy, foreign_key: :db_project_id
  has_many :repositories, :dependent => :destroy, foreign_key: :db_project_id
  has_many :messages, :as => :db_object, :dependent => :delete_all
  has_many :watched_projects, :dependent => :destroy

  has_many :linkedprojects, -> { order(:position) }, :class_name => "LinkedProject", foreign_key: :db_project_id
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,9 @@
   end
   class SaveError < APIException
     setup "project_save_error"
+  end
+  class WritePermissionError < APIException
+    setup "project_write_permission_error"
   end
   class ForbiddenError < APIException
     setup("change_project_protection_level", 403,
@@ -247,6 +250,15 @@
     end
   end
 
+  def check_write_access!
+    return if Rails.env.test? and User.current.nil? # for unit tests
+
+    # the can_create_check is inconsistent with package class check_write_access! check
+    unless User.current.can_modify_project?(self) || User.current.can_create_project?(self.name)
+      raise WritePermissionError, "No permission to modify project '#{self.name}' for user '#{User.current.login}'"
+    end
+  end
+
   def find_linking_projects
       sql =<<-END_SQL
       SELECT prj.*
@@ -289,6 +301,8 @@
   end
 
   def update_from_xml(xmlhash, force=nil)
+    check_write_access!
+
     # check for raising read access permissions, which can't get ensured atm
     unless self.new_record? || self.disabled_for?('access', nil, nil)
       if FlagHelper.xml_disabled_for?(xmlhash, 'access')
@@ -892,6 +906,8 @@
   end
 
   def add_user( user, role )
+    check_write_access!
+
     unless role.kind_of? Role
       role = Role.get_by_title(role)
     end
@@ -912,6 +928,8 @@
   end
 
   def add_group( group, role )
+    check_write_access!
+
     unless role.kind_of? Role
       role = Role.get_by_title(role)
     end
@@ -1523,6 +1541,8 @@
   end
 
   def set_project_type(project_type_name)
+    check_write_access!
+
     mytype = DbProjectType.find_by_name(project_type_name)
     return false unless mytype
     self.type_id = mytype.id
@@ -1535,6 +1555,8 @@
   end
 
   def set_maintenance_project(project)
+    check_write_access!
+
     if project.class == Project
       self.maintenance_project_id = project.id
       self.save!
@@ -1583,6 +1605,11 @@
 
   # called either directly or from delayed job
   def do_project_copy( params )
+    # set user if nil, needed for delayed job in Package model
+    User.current ||= User.find_by_login(params[:user])
+
+    check_write_access!
+
     # copy entire project in the backend
     begin
       path = "/source/#{URI.escape(self.name)}"
@@ -1593,9 +1620,6 @@
       # we need to check results of backend in any case (also timeout error eg)
     end
 
-    # set user if nil, needed for delayed job in Package model
-    User.current ||= User.find_by_login(params[:user])
-
     # restore all package meta data objects in DB
     backend_pkgs = Collection.find :package, :match => "@project='#{self.name}'"
     backend_pkgs.each_package do |package|
@@ -1611,6 +1635,8 @@
   def do_project_release( params )
     User.current ||= User.find_by_login(params[:user])
 
+    check_write_access!
+
     packages.each do |pkg|
       pkg.project.repositories.each do |repo|
         next if params[:repository] and params[:repository] != repo.name
@@ -1647,6 +1673,8 @@
   end
 
   def remove_role(what, role)
+    check_write_access!
+
     if what.kind_of? Group
       rel = self.project_group_role_relationships.where(bs_group_id: what.id)
     else
@@ -1660,6 +1688,8 @@
   end
  
   def add_role(what, role)
+    check_write_access!
+
     self.transaction do
       if what.kind_of? Group
         self.project_group_role_relationships.create!(role: role, group: what)
@@ -1684,6 +1714,8 @@
   end
 
   def update_patchinfo(patchinfo, opts = {})
+    check_write_access!
+
     opts[:enfore_issue_update] ||= false
 
     # collect bugnumbers from diff
@@ -1721,6 +1753,8 @@
   end
 
   def create_patchinfo_from_request(req)
+    check_write_access!
+
     patchinfo = Package.new(:name => "patchinfo", :title => "Patchinfo", :description => "Collected packages for update")
     self.packages << patchinfo
     patchinfo.add_flag("build", "enable", nil, nil)
@@ -1755,6 +1789,7 @@
 
   # updates packages automatically generated in the backend after submitting a product file
   def update_product_autopackages
+    check_write_access!
 
     backend_pkgs = Collection.find :id, :what => 'package', :match => "@project='#{self.name}' and starts-with(@name,'_product:')"
     b_pkg_index = backend_pkgs.each_package.inject(Hash.new) {|hash,elem| hash[elem.name] = elem; hash}
```
