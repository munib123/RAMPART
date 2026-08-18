# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 747_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `747_6`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 1-34 of the vulnerable file.

# frozen_string_literal: true

require_dependency 'rate_limiter'
require_dependency 'single_sign_on'
require_dependency 'single_sign_on_provider'
require_dependency 'url_helper'

class SessionController < ApplicationController
  class LocalLoginNotAllowed < StandardError; end
  rescue_from LocalLoginNotAllowed do
    render body: nil, status: 500
  end

  before_action :check_local_login_allowed, only: %i(create forgot_password email_login)
  before_action :rate_limit_login, only: %i(create email_login)
  skip_before_action :redirect_to_login_if_required
  skip_before_action :preload_json, :check_xhr, only: %i(sso sso_login sso_provider destroy email_login one_time_password)

  ACTIVATE_USER_KEY = "activate_user"

  def csrf
    render json: { csrf: form_authenticity_token }
  end

  def sso
    destination_url = cookies[:destination_url] || session[:destination_url]
    return_path = params[:return_path] || path('/')

    if destination_url && return_path == path('/')
      uri = URI::parse(destination_url)
      return_path = "#{uri.path}#{uri.query ? "?#{uri.query}" : ""}"
    end

    session.delete(:destination_url)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,10 +11,10 @@
     render body: nil, status: 500
   end
 
-  before_action :check_local_login_allowed, only: %i(create forgot_password email_login)
+  before_action :check_local_login_allowed, only: %i(create forgot_password email_login email_login_info)
   before_action :rate_limit_login, only: %i(create email_login)
   skip_before_action :redirect_to_login_if_required
-  skip_before_action :preload_json, :check_xhr, only: %i(sso sso_login sso_provider destroy email_login one_time_password)
+  skip_before_action :preload_json, :check_xhr, only: %i(sso sso_login sso_provider destroy one_time_password)
 
   ACTIVATE_USER_KEY = "activate_user"
 
@@ -305,49 +305,79 @@
     end
   end
 
+  def email_login_info
+    raise Discourse::NotFound if !SiteSetting.enable_local_logins_via_email
+
+    token = params[:token]
+    matched_token = EmailToken.confirmable(token)
+
+    if matched_token
+      response = {
+        can_login: true,
+        token: token,
+        token_email: matched_token.email
+      }
+
+      if matched_token.user&.totp_enabled?
+        response.merge!(
+          second_factor_required: true,
+          backup_codes_enabled: matched_token.user&.backup_codes_enabled?
+        )
+      end
+
+      render json: response
+    else
+      render json: {
+        can_login: false,
+        error: I18n.t('email_login.invalid_token')
+      }
+    end
+  end
+
   def email_login
     raise Discourse::NotFound if !SiteSetting.enable_local_logins_via_email
     second_factor_token = params[:second_factor_token]
     second_factor_method = params[:second_factor_method].to_i
     token = params[:token]
-    valid_token = !!EmailToken.valid_token_format?(token)
-    user = EmailToken.confirmable(token)&.user
-
-    if valid_token && user&.totp_enabled?
+    matched_token = EmailToken.confirmable(token)
+
+    if matched_token&.user&.totp_enabled?
       if !second_factor_token.present?
-        @second_factor_required = true
-        @backup_codes_enabled = true if user&.backup_codes_enabled?
-        return render layout: 'no_ember'
-      elsif !user.authenticate_second_factor(second_factor_token, second_factor_method)
+        return render json: { error: I18n.t('login.invalid_second_factor_code') }
+      elsif !matched_token.user.authenticate_second_factor(second_factor_token, second_factor_method)
         RateLimiter.new(nil, "second-factor-min-#{request.remote_ip}", 3, 1.minute).performed!
-        @error = I18n.t('login.invalid_second_factor_code')
-        return render layout: 'no_ember'
+        return render json: { error: I18n.t('login.invalid_second_factor_code') }
       end
     end
 
     if user = EmailToken.confirm(token)
       if login_not_approved_for?(user)
-        @error = login_not_approved[:error]
+        return render json: login_not_approved
       elsif payload = login_error_check(user)
-        @error = payload[:error]
+        return render json: payload
       else
         log_on_user(user)
+        return render json: success_json
+      end
+    end
+
+    return render json: { error: I18n.t('email_login.invalid_token') }
+  end
+
+  def one_time_password
+    @otp_username = otp_username = $redis.get "otp_#{params[:token]}"
+
+    if otp_username && user = User.find_by_username(otp_username)
+      if current_user&.username == otp_username
+        $redis.del "otp_#{params[:token]}"
         return redirect_to path("/")
-      end
-    else
-      @error = I18n.t('email_login.invalid_token')
-    end
-
-    render layout: 'no_ember'
-  end
-
-  def one_time_password
-    otp_username = $redis.get "otp_#{params[:token]}"
-
-    if otp_username && user = User.find_by_username(otp_username)
-      log_on_user(user)
-      $redis.del "otp_#{params[:token]}"
-      return redirect_to path("/")
+      elsif request.post?
+        log_on_user(user)
+        $redis.del "otp_#{params[:token]}"
+        return redirect_to path("/")
+      else
+        # Display the form
+      end
     else
       @error = I18n.t('user_api_key.invalid_token')
     end
```
