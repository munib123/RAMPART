# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 5837_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5837_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 1-27 of the vulnerable file.

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
class ApplicationController < ActionController::Base

  before_filter :set_context
  before_filter :clear_setting_cache
  before_filter "hook(:app_before_filter, self)"
  after_filter  "hook(:app_after_filter,  self)"

  helper_method :current_user_session, :current_user, :can_signup?
  helper_method :called_from_index_page?, :called_from_landing_page?
  helper_method :klass

  respond_to :html, :only => [ :index, :show, :auto_complete ]
  respond_to :js
  respond_to :json, :xml, :except => :edit
  respond_to :atom, :csv, :rss, :xls, :only => :index

  rescue_from ActiveRecord::RecordNotFound, :with => :respond_to_not_found
  rescue_from CanCan::AccessDenied,         :with => :respond_to_access_denied

  # Common auto_complete handler for all core controllers.
  #----------------------------------------------------------------------------
  def auto_complete
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,8 @@
 # See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
 #------------------------------------------------------------------------------
 class ApplicationController < ActionController::Base
+
+  protect_from_forgery
 
   before_filter :set_context
   before_filter :clear_setting_cache
```
