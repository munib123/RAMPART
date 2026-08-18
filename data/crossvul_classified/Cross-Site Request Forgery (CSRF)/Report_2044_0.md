# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 2044_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2044_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 1-35 of the vulnerable file.

# Filters added to this controller will be run for all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

require 'frontend_compat'

class Webui::WebuiController < ActionController::Base
  Rails.cache.set_domain if Rails.cache.respond_to?('set_domain')

  before_filter :setup_view_path
  before_filter :instantiate_controller_and_action_names
  before_filter :set_return_to, :reset_activexml, :authenticate
  before_filter :check_user
  before_filter :require_configuration
  after_filter :clean_cache

  # :notice and :alert are default, we add :success and :error
  add_flash_types :success, :error

  # FIXME: This belongs into the user controller my dear.
  # Also it would be better, but also more complicated, to just raise
  # HTTPPaymentRequired, UnauthorizedError or Forbidden
  # here so the exception handler catches it but what the heck...
  rescue_from ActiveXML::Transport::ForbiddenError do |exception|
    if exception.code == 'unregistered_ichain_user'
      render template: 'user/request_ichain' and return
    elsif exception.code == 'unregistered_user'
      render file: Rails.root.join('public/403'), formats: [:html], status: 402, layout: false and return
    elsif exception.code == 'unconfirmed_user'
      render file: Rails.root.join('public/402'), formats: [:html], status: 402, layout: false
    else
      if User.current.is_nobody?
        render file: Rails.root.join('public/401'), formats: [:html], status: :unauthorized, layout: false
      else
        render file: Rails.root.join('public/403'), formats: [:html], status: :forbidden, layout: false
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,15 @@
   before_filter :check_user
   before_filter :require_configuration
   after_filter :clean_cache
+
+  protect_from_forgery
+
+  # We execute both strategies here. The default rails strategy (resetting the session)
+  # and throwing an exception if the session is handled elswhere (e.g. proxy_auth_mode: :on)
+  def handle_unverified_request
+    super
+    raise ActionController::InvalidAuthenticityToken
+  end
 
   # :notice and :alert are default, we add :success and :error
   add_flash_types :success, :error
```
