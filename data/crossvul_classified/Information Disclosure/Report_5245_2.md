# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

module Taxonomix
  extend ActiveSupport::Concern
  include DirtyAssociations

  included do
    taxonomy_join_table = :taxable_taxonomies
    has_many taxonomy_join_table.to_sym, :dependent => :destroy, :as => :taxable
    has_many :locations, -> { where(:type => 'Location') },
             :through => taxonomy_join_table, :source => :taxonomy,
             :validate => false
    has_many :organizations, -> { where(:type => 'Organization') },
             :through => taxonomy_join_table, :source => :taxonomy,
             :validate => false
    after_initialize :set_current_taxonomy

    scoped_search :relation => :locations, :on => :name, :rename => :location, :complete_value => true
    scoped_search :relation => :locations, :on => :id, :rename => :location_id, :complete_enabled => false, :only_explicit => true, :validator => ScopedSearch::Validators::INTEGER
    scoped_search :relation => :organizations, :on => :name, :rename => :organization, :complete_value => true
    scoped_search :relation => :organizations, :on => :id, :rename => :organization_id, :complete_enabled => false, :only_explicit => true, :validator => ScopedSearch::Validators::INTEGER

    dirty_has_many_associations :organizations, :locations

    validate :ensure_taxonomies_not_escalated, :if => Proc.new { User.current.nil? || !User.current.admin? }
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,15 +1,15 @@
 module Taxonomix
   extend ActiveSupport::Concern
   include DirtyAssociations
+  TAXONOMY_JOIN_TABLE = :taxable_taxonomies
 
   included do
-    taxonomy_join_table = :taxable_taxonomies
-    has_many taxonomy_join_table.to_sym, :dependent => :destroy, :as => :taxable
+    has_many TAXONOMY_JOIN_TABLE, :dependent => :destroy, :as => :taxable
     has_many :locations, -> { where(:type => 'Location') },
-             :through => taxonomy_join_table, :source => :taxonomy,
+             :through => TAXONOMY_JOIN_TABLE, :source => :taxonomy,
              :validate => false
     has_many :organizations, -> { where(:type => 'Organization') },
-             :through => taxonomy_join_table, :source => :taxonomy,
+             :through => TAXONOMY_JOIN_TABLE, :source => :taxonomy,
              :validate => false
     after_initialize :set_current_taxonomy
 
@@ -28,10 +28,11 @@
 
     # default inner_method includes children (subtree_ids)
     def with_taxonomy_scope(loc = Location.current, org = Organization.current, inner_method = :subtree_ids)
+      scope = block_given? ? yield : where(nil)
+      return scope unless Taxonomy.enabled_taxonomies.present?
       self.which_ancestry_method = inner_method
       self.which_location        = Location.expand(loc) if SETTINGS[:locations_enabled]
       self.which_organization    = Organization.expand(org) if SETTINGS[:organizations_enabled]
-      scope = block_given? ? yield : where('1=1')
       scope = scope_by_taxable_ids(scope)
       scope.readonly(false)
     end
@@ -69,26 +70,45 @@
     end
 
     def taxable_ids(loc = which_location, org = which_organization, inner_method = which_ancestry_method)
-      if SETTINGS[:locations_enabled] && loc.present?
-        inner_ids_loc = if Location.ignore?(self.to_s)
-                          self.unscoped.pluck("#{table_name}.id")
-                        else
-                          inner_select(loc, inner_method)
-                        end
-      end
-      if SETTINGS[:organizations_enabled] && org.present?
-        inner_ids_org = if Organization.ignore?(self.to_s)
-                          self.unscoped.pluck("#{table_name}.id")
-                        else
-                          inner_select(org, inner_method)
-                        end
-      end
-      inner_ids   = inner_ids_loc & inner_ids_org if (inner_ids_loc && inner_ids_org)
-      inner_ids ||= inner_ids_loc if inner_ids_loc
-      inner_ids ||= inner_ids_org if inner_ids_org
-      # In the case of users we want the taxonomy scope to get both the users of the taxonomy and admins.
-      inner_ids.concat(admin_ids) if inner_ids && self == User
-      inner_ids
+      # Return everything (represented by nil), including objects without
+      # taxonomies. This value should only be returned for admin users.
+      return nil if any_context?(loc) && any_context?(org) &&
+        User.current.try(:admin?)
+
+      ids = unscoped.pluck(:id)
+      ids &= inner_ids(loc, Location, inner_method) if SETTINGS[:locations_enabled]
+      ids &= inner_ids(org, Organization, inner_method) if SETTINGS[:organizations_enabled]
+
+      if self == User
+        # In the case of users we want the taxonomy scope to get both the users
+        # of the taxonomy, admins, and the current user.
+        ids.concat(admin_ids)
+        ids << User.current.id if User.current.present?
+      end
+
+      ids
+    end
+
+    # Returns the IDs available for the passed context.
+    # Passing a nil or [] value as taxonomy equates to "Any context".
+    # Any other value will be understood as 'IDs available in this taxonomy'.
+    def inner_ids(taxonomy, taxonomy_class, inner_method)
+      return unscoped.pluck("#{table_name}.id") if taxonomy_class.ignore?(to_s)
+      return inner_select(taxonomy, inner_method) if taxonomy.present?
+      return [] unless User.current.present?
+      # Any available taxonomy to the current user
+      return unscoped.pluck("#{table_name}.id") if User.current.admin?
+
+      taxonomy_relation = taxonomy_class.to_s.underscore.pluralize
+      any_context_taxonomies = User.current.
+        taxonomy_and_child_ids(:"#{taxonomy_relation}")
+      unscoped.joins(TAXONOMY_JOIN_TABLE).
+        where("#{TAXONOMY_JOIN_TABLE}.taxonomy_id" => any_context_taxonomies).
+        pluck(:id)
+    end
+
+    def any_context?(taxonomy)
+      taxonomy.blank?
     end
 
     # taxonomy can be either specific taxonomy object or array of these objects
```
