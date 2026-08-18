# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5665_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5665_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-36 of the vulnerable file.

module Spree
  module Admin
    class UsersController < ResourceController
      rescue_from Spree::User::DestroyWithOrdersError, :with => :user_destroy_with_orders_error

      update.after :sign_in_if_change_own_password

      # http://spreecommerce.com/blog/2010/11/02/json-hijacking-vulnerability/
      before_filter :check_json_authenticity, :only => :index
      before_filter :load_roles, :only => [:edit, :new, :update, :create, :generate_api_key, :clear_api_key]

      def index
        respond_with(@collection) do |format|
          format.html
          format.json { render :json => json_data }
        end
      end

      def generate_api_key
        if @user.generate_spree_api_key!
          flash.notice = t('key_generated', :scope => 'spree.api')
        end
        redirect_to edit_admin_user_path(@user)
      end

      def clear_api_key
        if @user.clear_spree_api_key!
          flash.notice = t('key_cleared', :scope => 'spree.api')
        end
        redirect_to edit_admin_user_path(@user)
      end


      protected

        def collection
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,47 @@
         respond_with(@collection) do |format|
           format.html
           format.json { render :json => json_data }
+        end
+      end
+
+      def create
+        if params[:user]
+          roles = params[:user].delete("spree_role_ids")
+        end
+
+        @user = Spree::User.new(params[:user])
+        if @user.save
+
+          if roles
+            @user.spree_roles = roles.reject(&:blank?).collect{|r| Spree::Role.find(r)}
+          end
+
+          flash.now[:notice] = t(:created_successfully)
+          render :edit
+        else
+          render :new
+        end
+      end
+
+      def update
+        if params[:user]
+          roles = params[:user].delete("spree_role_ids")
+        end
+
+        if @user.update_attributes(params[:user])
+          if roles
+            @user.spree_roles = roles.reject(&:blank?).collect{|r| Spree::Role.find(r)}
+          end
+
+          if params[:user][:password].present?
+            # this logic needed b/c devise wants to log us out after password changes
+            user = Spree::User.reset_password_by_token(params[:user])
+            sign_in(@user, :event => :authentication, :bypass => !Spree::Auth::Config[:signout_after_password_change])
+          end
+          flash.now[:notice] = t(:account_updated)
+          render :edit
+        else
+          render :edit
         end
       end
 
```
