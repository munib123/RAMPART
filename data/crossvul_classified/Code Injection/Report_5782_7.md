# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_7
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_7`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 1-39 of the vulnerable file.

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

# Controller for logging in and logging out of the application. See
# {AuthenticationHelpers} for more information on how authentication works.

class SessionsController < ApplicationController
  skip_before_filter :login_required, except: :destroy
  before_filter :must_be_unauthenticated, except: :destroy

  respond_to :html

  # Displays a page where the user can enter his/her credentials to log in.
  #
  # Routes
  # ------
  #
  # * `GET /login`

  def new
  end

  # Attempts to log a user in. If login fails, or the LDAP server is
  # unreachable, renders the `new` page with a flash alert.
  #
  # If the login is successful, takes the user to the next URL stored in the
  # params; or, if none is set, the root URL.
  #
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,7 +16,7 @@
 # {AuthenticationHelpers} for more information on how authentication works.
 
 class SessionsController < ApplicationController
-  skip_before_filter :login_required, except: :destroy
+  skip_before_filter :login_required, only: [:new, :create]
   before_filter :must_be_unauthenticated, except: :destroy
 
   respond_to :html
```
