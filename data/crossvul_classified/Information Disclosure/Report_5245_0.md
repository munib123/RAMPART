# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 13-53 of the vulnerable file.

      skip_before_action :session_expiry, :update_activity_time, :only => actions
      before_action(:only => actions) { require_smart_proxy_or_login(options[:features]) }
      attr_reader :detected_proxy

      define_method(:require_ssl_with_smart_proxy_filters?) do
        if [actions].flatten.map(&:to_s).include?(self.action_name)
          false
        else
          require_ssl_without_smart_proxy_filters?
        end
      end
      alias_method_chain :require_ssl?, :smart_proxy_filters
    end
  end

  private

  # Permits registered Smart Proxies or a user with permission
  def require_smart_proxy_or_login(features = nil)
    features = features.call if features.respond_to?(:call)
    allowed_smart_proxies = features.blank? ? SmartProxy.all : SmartProxy.with_features(*features)

    if !Setting[:restrict_registered_smart_proxies] || auth_smart_proxy(allowed_smart_proxies, Setting[:require_ssl_smart_proxies])
      set_admin_user
      return true
    end

    require_login
    unless User.current
      render_error 'access_denied', :status => :forbidden unless performed? && api_request?
      return false
    end
    authorize
  end

  # Filter requests to only permit from hosts with a registered smart proxy
  # Uses rDNS of the request to match proxy hostnames
  def auth_smart_proxy(proxies = SmartProxy.all, require_cert = true)
    request_hosts = nil
    if request.ssl?
      # If we have the client certficate in the request environment we can extract the dn and sans from there
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,11 @@
   # Permits registered Smart Proxies or a user with permission
   def require_smart_proxy_or_login(features = nil)
     features = features.call if features.respond_to?(:call)
-    allowed_smart_proxies = features.blank? ? SmartProxy.all : SmartProxy.with_features(*features)
+    allowed_smart_proxies = if features.blank?
+                              SmartProxy.unscoped.all
+                            else
+                              SmartProxy.unscoped.with_features(*features)
+                            end
 
     if !Setting[:restrict_registered_smart_proxies] || auth_smart_proxy(allowed_smart_proxies, Setting[:require_ssl_smart_proxies])
       set_admin_user
@@ -47,7 +51,7 @@
 
   # Filter requests to only permit from hosts with a registered smart proxy
   # Uses rDNS of the request to match proxy hostnames
-  def auth_smart_proxy(proxies = SmartProxy.all, require_cert = true)
+  def auth_smart_proxy(proxies = SmartProxy.unscoped.all, require_cert = true)
     request_hosts = nil
     if request.ssl?
       # If we have the client certficate in the request environment we can extract the dn and sans from there
```
