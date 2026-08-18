# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_8
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_8`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-32 of the vulnerable file.

# Copyright 2012 Square Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# Adds LDAP-based authentication to the {User} model. Mixed in if this
# Squash install is configured to use LDAP-based authentication.

module LdapAuthentication

  # @return [String] This user's LDAP distinguished name (DN).

  def distinguished_name
    "#{Squash::Configuration.authentication.ldap.search_key}=#{username},#{Squash::Configuration.authentication.ldap.tree_base}"
  end

  private

  def create_primary_email
    emails.create!({email: "#{username}@#{Squash::Configuration.mailer.domain}", primary: true}, as: :system)
  end
end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,11 @@
 # Squash install is configured to use LDAP-based authentication.
 
 module LdapAuthentication
+  extend ActiveSupport::Concern
+
+  included do
+    attr_accessible :first_name, :last_name, as: :system
+  end
 
   # @return [String] This user's LDAP distinguished name (DN).
 
```
