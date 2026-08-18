# CrossVul Fix Pair: Insufficient Session Expiration in ruby
**Pair ID:** 2590_0
**Vulnerability Class:** Insufficient Session Expiration
**CWE:** CWE-613
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2590_0`)

## Vulnerability Information & PoC

## Description
Insufficient Session Expiration - According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

## Vulnerable Code
```ruby
Lines 25-65 of the vulnerable file.

# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# See doc/COPYRIGHT.rdoc for more details.
#++

require 'uri'
require 'cgi'

class ApplicationController < ActionController::Base
  class_attribute :_model_object
  class_attribute :_model_scope
  class_attribute :accept_key_auth_actions

  helper_method :render_to_string

  protected

  include I18n
  include Redmine::I18n
  include HookHelper

  layout 'base'

  protect_from_forgery
  # CSRF protection prevents two things. It prevents an attacker from using a
  # user's session to execute requests. It also prevents an attacker to log in
  # a user with the attacker's account. API requests each contain their own
  # authentication token, e.g. as key parameter or header, so they don't have
  # to be protected by CSRF protection as long as they don't create a session
  #
  # We can't reliably determine here whether a request is an API
  # request as this happens in our way too complex find_current_user method
  # that is only executed after this method. E.g we might have to check that
  # no session is active and that no autologin cookie is set.
  #
  # Thus, we always reset any active session and the autologin cookie to make
  # sure find_current user doesn't find a user based on an active session.
  #
  # Nevertheless, API requests should not be aborted, which they would be
  # if we raised an error here. Still, users should see an error message
  # when sending a form with a wrong CSRF token (e.g. after session expiration).
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,7 @@
   include I18n
   include Redmine::I18n
   include HookHelper
+  include ::OpenProject::Authentication::SessionExpiry
 
   layout 'base'
 
@@ -675,13 +676,7 @@
   private
 
   def session_expired?
-    !api_request? && current_user.logged? &&
-      (session_ttl_enabled? && (session[:updated_at].nil? ||
-                               (session[:updated_at] + Setting.session_ttl.to_i.minutes) < Time.now))
-  end
-
-  def session_ttl_enabled?
-    Setting.session_ttl_enabled? && Setting.session_ttl.to_i >= 5
+    !api_request? && current_user.logged? && session_ttl_expired?
   end
 
   def permitted_params
```
