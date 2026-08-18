# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 32-73 of the vulnerable file.

    before_validation :set_default_user

    validates :name, :presence   => true, :uniqueness => true, :format => {:with => Net::Validations::HOST_REGEXP}
    validates :owner_type, :inclusion => { :in          => OWNER_TYPES,
                                           :allow_blank => true,
                                           :message     => (_("Owner type needs to be one of the following: %s") % OWNER_TYPES.join(', ')) }
    validate :validate_owner
    validate :host_has_required_interfaces
    validate :uniq_interfaces_identifiers
    validate :build_managed_only
    validate :owner_taxonomies_match, :if => Proc.new { |host| host.owner.is_a?(User) }

    include PxeLoaderSuggestion

    default_scope -> { where(taxonomy_conditions) }

    def self.taxonomy_conditions
      org = Organization.expand(Organization.current) if SETTINGS[:organizations_enabled]
      loc = Location.expand(Location.current) if SETTINGS[:locations_enabled]
      conditions = {}
      conditions[:organization_id] = Array(org).map { |o| o.subtree_ids }.flatten.uniq if org.present?
      conditions[:location_id] = Array(loc).map { |l| l.subtree_ids }.flatten.uniq if loc.present?
      conditions
    end

    scope :no_location,     -> { rewhere(:location_id => nil) }
    scope :no_organization, -> { rewhere(:organization_id => nil) }

    PRIMARY_INTERFACE_ATTRIBUTES = [:name, :ip, :ip6, :mac,
                                    :subnet, :subnet_id, :subnet_name,
                                    :subnet6, :subnet6_id, :subnet6_name,
                                    :domain, :domain_id, :domain_name,
                                    :lookup_values_attributes].freeze

    # primary interface is mandatory because of delegated methods so we build it if it's missing
    # similar for provision interface
    # we can't set name attribute until we have primary interface so we don't pass it to super
    # initializer and we set name when we are sure that we have primary interface
    # we can't create primary interface before calling super because args may contain nested
    # interface attributes
    def initialize(*args)
      values_for_primary_interface = {}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,8 +49,8 @@
       org = Organization.expand(Organization.current) if SETTINGS[:organizations_enabled]
       loc = Location.expand(Location.current) if SETTINGS[:locations_enabled]
       conditions = {}
-      conditions[:organization_id] = Array(org).map { |o| o.subtree_ids }.flatten.uniq if org.present?
-      conditions[:location_id] = Array(loc).map { |l| l.subtree_ids }.flatten.uniq if loc.present?
+      conditions[:organization_id] = Array(org).map { |o| o.subtree_ids }.flatten.uniq unless org.nil?
+      conditions[:location_id] = Array(loc).map { |l| l.subtree_ids }.flatten.uniq unless loc.nil?
       conditions
     end
 
```
