# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 10-50 of the vulnerable file.

               :smart_proxy_ids, :user_ids, :provisioning_template_ids,
               :realm_ids, :ptable_ids]

  def initialize(taxonomy, hosts = nil)
    @taxonomy = taxonomy
    @hosts    = hosts.nil? ? @taxonomy.hosts.includes(:interfaces) : Host.where(:id => Array.wrap(hosts).map(&:id)).includes(:interfaces)
  end

  attr_reader :taxonomy, :hosts

  # returns a hash of HASH_KEYS used ids by hosts in a given taxonomy
  def used_ids
    @used_ids = default_ids_hash(true)
  end

  def selected_ids
    return @selected_ids if @selected_ids
    ids = default_ids_hash
    #types NOT ignored - get ids that are selected
    hash_keys.each do |col|
      ids[col] = Array(taxonomy.send(col))
    end
    #types that ARE ignored - get ALL ids for object
    Array(taxonomy.ignore_types).each do |taxonomy_type|
      ids["#{taxonomy_type.tableize.singularize}_ids"] = taxonomy_type.constantize.pluck(:id)
    end

    ids["#{opposite_taxonomy_type}_ids"] = Array(taxonomy.send("#{opposite_taxonomy_type}_ids"))
    @selected_ids                        = ids
  end

  def used_and_selected_ids
    @used_and_selected_ids ||= HashWithIndifferentAccess.new(Hash[hash_keys.map do |col|
      if taxonomy.ignore?(hash_key_to_class(col))
        [col, used_ids[col]] # used_ids only if ignore selected
      else
        [col, used_ids[col] & selected_ids[col]] # & operator to intersect COMMON elements of arrays
      end
    end])
  end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,11 +27,11 @@
     ids = default_ids_hash
     #types NOT ignored - get ids that are selected
     hash_keys.each do |col|
-      ids[col] = Array(taxonomy.send(col))
+      ids[col] = Array(taxonomy.send(col)).uniq
     end
     #types that ARE ignored - get ALL ids for object
     Array(taxonomy.ignore_types).each do |taxonomy_type|
-      ids["#{taxonomy_type.tableize.singularize}_ids"] = taxonomy_type.constantize.pluck(:id)
+      ids["#{taxonomy_type.tableize.singularize}_ids"] = taxonomy_type.constantize.pluck(:id).uniq
     end
 
     ids["#{opposite_taxonomy_type}_ids"] = Array(taxonomy.send("#{opposite_taxonomy_type}_ids"))
@@ -213,7 +213,7 @@
   def default_ids_hash(populate_values = false)
     ids = HashWithIndifferentAccess.new
     hash_keys.each do |col|
-      ids[col] = populate_values ? Array(self.send(col)) : []
+      ids[col] = populate_values ? Array(self.send(col)).uniq : []
     end
     ids
   end
```
