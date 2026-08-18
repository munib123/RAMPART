# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 5763_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5763_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 95-135 of the vulnerable file.

        end
      end

      # NOTE if we're using code from the signed request
      # then FB sets the redirect_uri to '' during the authorize
      # phase + it must match during the access_token phase:
      # https://github.com/facebook/php-sdk/blob/master/src/base_facebook.php#L348
      def callback_url
        if @authorization_code_from_signed_request
          ''
        else
          options[:callback_url] || super
        end
      end

      def access_token_options
        options.access_token_options.inject({}) { |h,(k,v)| h[k.to_sym] = v; h }
      end

      ##
      # You can pass +display+, +state+ or +scope+ params to the auth request, if
      # you need to set them dynamically. You can also set these options
      # in the OmniAuth config :authorize_params option.
      #
      # /auth/facebook?display=popup&state=ABC
      #
      def authorize_params
        super.tap do |params|
          %w[display state scope].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]

              # to support omniauth-oauth2's auto csrf protection
              session['omniauth.state'] = params[:state] if v == 'state'
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,7 +112,7 @@
       end
 
       ##
-      # You can pass +display+, +state+ or +scope+ params to the auth request, if
+      # You can pass +display+ or +scope+ params to the auth request, if
       # you need to set them dynamically. You can also set these options
       # in the OmniAuth config :authorize_params option.
       #
@@ -120,12 +120,9 @@
       #
       def authorize_params
         super.tap do |params|
-          %w[display state scope].each do |v|
+          %w[display scope].each do |v|
             if request.params[v]
               params[v.to_sym] = request.params[v]
-
-              # to support omniauth-oauth2's auto csrf protection
-              session['omniauth.state'] = params[:state] if v == 'state'
             end
           end
 
```
