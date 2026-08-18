# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 747_11
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `747_11`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 320-360 of the vulnerable file.


  get "review" => "reviewables#index" # For ember app
  get "review/:reviewable_id" => "reviewables#show", constraints: { reviewable_id: /\d+/ }
  get "review/topics" => "reviewables#topics"
  get "review/settings" => "reviewables#settings"
  put "review/settings" => "reviewables#settings"
  put "review/:reviewable_id/perform/:action_id" => "reviewables#perform", constraints: {
    reviewable_id: /\d+/,
    action_id: /[a-z\_]+/
  }
  put "review/:reviewable_id" => "reviewables#update", constraints: { reviewable_id: /\d+/ }
  delete "review/:reviewable_id" => "reviewables#destroy", constraints: { reviewable_id: /\d+/ }

  resources :reviewable_claimed_topics

  get "session/sso" => "session#sso"
  get "session/sso_login" => "session#sso_login"
  get "session/sso_provider" => "session#sso_provider"
  get "session/current" => "session#current"
  get "session/csrf" => "session#csrf"
  get "session/email-login/:token" => "session#email_login"
  post "session/email-login/:token" => "session#email_login"
  get "session/otp/:token" => "session#one_time_password", constraints: { token: /[0-9a-f]+/ }
  get "composer_messages" => "composer_messages#index"
  post "composer/parse_html" => "composer#parse_html"

  resources :static
  post "login" => "static#enter", constraints: { format: /(json|html)/ }
  get "login" => "static#show", id: "login", constraints: { format: /(json|html)/ }
  get "password-reset" => "static#show", id: "password_reset", constraints: { format: /(json|html)/ }
  get "faq" => "static#show", id: "faq", constraints: { format: /(json|html)/ }
  get "tos" => "static#show", id: "tos", as: 'tos', constraints: { format: /(json|html)/ }
  get "privacy" => "static#show", id: "privacy", as: 'privacy', constraints: { format: /(json|html)/ }
  get "signup" => "static#show", id: "signup", constraints: { format: /(json|html)/ }
  get "login-preferences" => "static#show", id: "login", constraints: { format: /(json|html)/ }

  %w{guidelines rules conduct}.each do |faq_alias|
    get faq_alias => "static#show", id: "guidelines", as: faq_alias, constraints: { format: /(json|html)/ }
  end

  get "my/*path", to: 'users#my_redirect'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -337,9 +337,10 @@
   get "session/sso_provider" => "session#sso_provider"
   get "session/current" => "session#current"
   get "session/csrf" => "session#csrf"
-  get "session/email-login/:token" => "session#email_login"
+  get "session/email-login/:token" => "session#email_login_info"
   post "session/email-login/:token" => "session#email_login"
   get "session/otp/:token" => "session#one_time_password", constraints: { token: /[0-9a-f]+/ }
+  post "session/otp/:token" => "session#one_time_password", constraints: { token: /[0-9a-f]+/ }
   get "composer_messages" => "composer_messages#index"
   post "composer/parse_html" => "composer#parse_html"
 
```
