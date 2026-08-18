# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 4056_5
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4056_5`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 1-27 of the vulnerable file.

# Copyright (C) 2012-2016 Zammad Foundation, http://zammad-foundation.org/

class UsersController < ApplicationController
  include ChecksUserAttributesByCurrentUserPermission

  prepend_before_action -> { authorize! }, only: %i[import_example import_start search history]
  prepend_before_action :authentication_check, except: %i[create password_reset_send password_reset_verify image]
  prepend_before_action :authentication_check_only, only: [:create]

  # @path       [GET] /users
  #
  # @summary          Returns a list of User records.
  # @notes            The requester has to be in the role 'Admin' or 'Agent' to
  #                   get a list of all Users. If the requester is in the
  #                   role 'Customer' only just the own User record will be returned.
  #
  # @response_message 200 [Array<User>] List of matching User records.
  # @response_message 401               Invalid session.
  def index
    offset = 0
    per_page = 500
    if params[:page] && params[:per_page]
      offset = (params[:page].to_i - 1) * params[:per_page].to_i
      per_page = params[:per_page].to_i
    end

    if per_page > 500
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
   include ChecksUserAttributesByCurrentUserPermission
 
   prepend_before_action -> { authorize! }, only: %i[import_example import_start search history]
-  prepend_before_action :authentication_check, except: %i[create password_reset_send password_reset_verify image]
+  prepend_before_action :authentication_check, except: %i[create password_reset_send password_reset_verify image email_verify email_verify_send]
   prepend_before_action :authentication_check_only, only: [:create]
 
   # @path       [GET] /users
@@ -139,6 +139,15 @@
       # check if user already exists
       exists = User.exists?(email: clean_params[:email].downcase.strip)
       raise Exceptions::UnprocessableEntity, "Email address '#{clean_params[:email].downcase.strip}' is already used for other user." if exists
+
+      # check password policy
+      if clean_params[:password].present?
+        result = password_policy(clean_params[:password])
+        if result != true
+          render json: { error: result }, status: :unprocessable_entity
+          return
+        end
+      end
 
       user = User.new(clean_params)
       user.associations_from_param(params)
@@ -499,6 +508,8 @@
     user = User.signup_verify_via_token(params[:token], current_user)
     raise Exceptions::UnprocessableEntity, 'Invalid token!' if !user
 
+    current_user_set(user)
+
     render json: { message: 'ok', user_email: user.email }, status: :ok
   end
 
@@ -527,16 +538,11 @@
     raise Exceptions::UnprocessableEntity, 'No email!' if !params[:email]
 
     user = User.find_by(email: params[:email].downcase)
-    if !user
+    if !user || user.verified == true
       # result is always positive to avoid leaking of existing user accounts
       render json: { message: 'ok' }, status: :ok
       return
     end
-
-    #if user.verified == true
-    #  render json: { error: 'Already verified!' }, status: :unprocessable_entity
-    #  return
-    #end
 
     Token.create(action: 'Signup', user_id: user.id)
 
@@ -1029,13 +1035,13 @@
 
   def password_policy(password)
     if Setting.get('password_min_size').to_i > password.length
-      return ["Can\'t update password, it must be at least %s characters long!", Setting.get('password_min_size')]
+      return ['Invalid password, it must be at least %s characters long!', Setting.get('password_min_size')]
     end
     if Setting.get('password_need_digit').to_i == 1 && password !~ /\d/
-      return ["Can't update password, it must contain at least 1 digit!"]
+      return ['Invalid password, it must contain at least 1 digit!']
     end
     if Setting.get('password_min_2_lower_2_upper_characters').to_i == 1 && ( password !~ /[A-Z].*[A-Z]/ || password !~ /[a-z].*[a-z]/ )
-      return ["Can't update password, it must contain at least 2 lowercase and 2 uppercase characters!"]
+      return ['Invalid password, it must contain at least 2 lowercase and 2 uppercase characters!']
     end
 
     true
```
