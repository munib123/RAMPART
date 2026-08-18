# CrossVul Fix Pair: Permission Issues in ruby
**Pair ID:** 5709_1
**Vulnerability Class:** Permission Issues
**CWE:** CWE-275
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5709_1`)

## Vulnerability Information & PoC

## Description
Permission Issues

## Vulnerable Code
```ruby
Lines 1-37 of the vulnerable file.

# -*- encoding: utf-8 i*-
require 'api_exception'
require 'builder/xchar'

class Package < ActiveRecord::Base
  include FlagHelper

  class CycleError < APIException
   setup "cycle_error"
  end
  class DeleteError < APIException
    attr_accessor :packages
    setup "delete_error"
  end
  class SaveError < APIException
    setup "package_save_error"
  end
  class ReadAccessError < APIException
    setup 'unknown_package', 404, "Unknown package"
  end
  class UnknownObjectError < APIException
    setup 'unknown_package', 404, "Unknown package"
  end
  class ReadSourceAccessError < APIException
    setup 'source_access_no_permission', 403, "Source Access not allowed"
  end
  belongs_to :project, foreign_key: :db_project_id

  has_many :package_user_role_relationships, :dependent => :destroy, foreign_key: :db_package_id
  has_many :package_group_role_relationships, :dependent => :destroy, foreign_key: :db_package_id
  has_many :messages, :as => :db_object, :dependent => :destroy

  has_many :taggings, :as => :taggable, :dependent => :destroy
  has_many :tags, :through => :taggings

  has_many :download_stats
  has_many :ratings, :as => :db_object, :dependent => :destroy
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,9 @@
   end
   class SaveError < APIException
     setup "package_save_error"
+  end
+  class WritePermissionError < APIException
+    setup "package_write_permission_error"
   end
   class ReadAccessError < APIException
     setup 'unknown_package', 404, "Unknown package"
@@ -239,6 +242,14 @@
     return self.project.is_locked?
   end
 
+  def check_write_access!
+    return if Rails.env.test? and User.current.nil? # for unit tests
+
+    unless User.current.can_modify_package? self
+      raise WritePermissionError, "No permission to modify package '#{self.name}' for user '#{User.current.login}'"
+    end
+  end
+
   # NOTE: this is no permission check, should it be added ?
   def can_be_deleted?
     # check if other packages have me as devel package
@@ -285,14 +296,17 @@
   end
 
   def add_package_kind( kinds )
+    check_write_access!
     private_set_package_kind( kinds, nil, true )
   end
 
   def set_package_kind( kinds = nil )
+    check_write_access!
     private_set_package_kind( kinds )
   end
 
   def set_package_kind_from_commit( commit )
+    check_write_access!
     private_set_package_kind( nil, commit )
   end
 
@@ -419,6 +433,7 @@
   end
 
   def update_from_xml( xmlhash )
+    check_write_access!
     self.title = xmlhash.value('title')
     self.description = xmlhash.value('description')
     self.bcntsynctag = nil
@@ -616,6 +631,7 @@
   end
 
   def store(opts = {})
+    # no write access check here, since this operation may will disable this permission ...
     @commit_opts = opts
     save!
   end
@@ -649,6 +665,7 @@
   end
 
   def add_user( user, role )
+    check_write_access!
     unless role.kind_of? Role
       role = Role.get_by_title(role)
     end
@@ -669,6 +686,7 @@
   end
 
   def add_group( group, role )
+    check_write_access!
     unless role.kind_of? Role
       role = Role.get_by_title(role)
     end
@@ -933,14 +951,17 @@
   end
 
   def remove_all_persons
+    check_write_access!
     self.package_user_role_relationships.delete_all
   end
 
   def remove_all_groups
+    check_write_access!
     self.package_group_role_relationships.delete_all
   end
 
   def remove_role(what, role)
+    check_write_access!
     if what.kind_of? Group
       rel = self.package_group_role_relationships.where(bs_group_id: what.id)
     else
@@ -954,6 +975,7 @@
   end
 
   def add_role(what, role)
+    check_write_access!
     self.transaction do
       if what.kind_of? Group
         self.package_group_role_relationships.create!(role: role, group: what)
```
