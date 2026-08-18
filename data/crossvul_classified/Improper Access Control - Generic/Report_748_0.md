# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 748_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `748_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 348-388 of the vulnerable file.

        RateLimiter.new(nil, "second-factor-min-#{request.remote_ip}", 3, 1.minute).performed!
        return render json: { error: I18n.t('login.invalid_second_factor_code') }
      end
    end

    if user = EmailToken.confirm(token)
      if login_not_approved_for?(user)
        return render json: login_not_approved
      elsif payload = login_error_check(user)
        return render json: payload
      else
        log_on_user(user)
        return render json: success_json
      end
    end

    return render json: { error: I18n.t('email_login.invalid_token') }
  end

  def one_time_password
    otp_username = $redis.get "otp_#{params[:token]}"

    if otp_username && user = User.find_by_username(otp_username)
      log_on_user(user)
      $redis.del "otp_#{params[:token]}"
      return redirect_to path("/")
    else
      @error = I18n.t('user_api_key.invalid_token')
    end

    render layout: 'no_ember'
  end

  def forgot_password
    params.require(:login)

    RateLimiter.new(nil, "forgot-password-hr-#{request.remote_ip}", 6, 1.hour).performed!
    RateLimiter.new(nil, "forgot-password-min-#{request.remote_ip}", 3, 1.minute).performed!

    RateLimiter.new(nil, "forgot-password-login-hour-#{params[:login].to_s[0..100]}", 12, 1.hour).performed!
    RateLimiter.new(nil, "forgot-password-login-min-#{params[:login].to_s[0..100]}", 3, 1.minute).performed!
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -365,12 +365,19 @@
   end
 
   def one_time_password
-    otp_username = $redis.get "otp_#{params[:token]}"
+    @otp_username = otp_username = $redis.get "otp_#{params[:token]}"
 
     if otp_username && user = User.find_by_username(otp_username)
-      log_on_user(user)
-      $redis.del "otp_#{params[:token]}"
-      return redirect_to path("/")
+      if current_user&.username == otp_username
+        $redis.del "otp_#{params[:token]}"
+        return redirect_to path("/")
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
