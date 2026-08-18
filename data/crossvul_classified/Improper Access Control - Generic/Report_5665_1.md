# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5665_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5665_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-37 of the vulnerable file.

module Spree
  class User < ActiveRecord::Base
    include Core::UserBanners

    devise :database_authenticatable, :token_authenticatable, :registerable, :recoverable,
           :rememberable, :trackable, :validatable, :encryptable, :encryptor => 'authlogic_sha512'

    has_many :orders
    belongs_to :ship_address, :foreign_key => 'ship_address_id', :class_name => 'Spree::Address'
    belongs_to :bill_address, :foreign_key => 'bill_address_id', :class_name => 'Spree::Address'

    before_save :check_admin
    before_validation :set_login
    before_destroy :check_completed_orders

    # Setup accessible (or protected) attributes for your model
    attr_accessible :email, :password, :password_confirmation, :remember_me, :persistence_token, :login, :spree_role_ids

    users_table_name = User.table_name
    roles_table_name = Role.table_name

    scope :admin, lambda { includes(:spree_roles).where("#{roles_table_name}.name" => "admin") }
    scope :registered, where("#{users_table_name}.email NOT LIKE ?", "%@example.net")

    class DestroyWithOrdersError < StandardError; end

    # Creates an anonymous user.  An anonymous user is basically an auto-generated +User+ account that is created for the customer
    # behind the scenes and its completely transparently to the customer.  All +Orders+ must have a +User+ so this is necessary
    # when adding to the "cart" (which is really an order) and before the customer has a chance to provide an email or to register.
    def self.anonymous!
      token = User.generate_token(:persistence_token)
      User.create(:email => "#{token}@example.net", :password => token, :password_confirmation => token, :persistence_token => token)
    end

    def self.admin_created?
      User.admin.count > 0
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
     before_destroy :check_completed_orders
 
     # Setup accessible (or protected) attributes for your model
-    attr_accessible :email, :password, :password_confirmation, :remember_me, :persistence_token, :login, :spree_role_ids
+    attr_accessible :email, :password, :password_confirmation, :remember_me, :persistence_token, :login
 
     users_table_name = User.table_name
     roles_table_name = Role.table_name
```
