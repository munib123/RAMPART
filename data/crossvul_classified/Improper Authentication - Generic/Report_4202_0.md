# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 4202_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4202_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 36-76 of the vulnerable file.


        def collection_paginator
          Spree::Api::Dependencies.storefront_collection_paginator.constantize
        end

        def render_serialized_payload(status = 200)
          render json: yield, status: status, content_type: content_type
        rescue ArgumentError => exception
          render_error_payload(exception.message, 400)
        end

        def render_error_payload(error, status = 422)
          if error.is_a?(Struct)
            render json: { error: error.to_s, errors: error.to_h }, status: status, content_type: content_type
          elsif error.is_a?(String)
            render json: { error: error }, status: status, content_type: content_type
          end
        end

        def spree_current_user
          @spree_current_user ||= Spree.user_class.find_by(id: doorkeeper_token.resource_owner_id) if doorkeeper_token
        end

        def spree_authorize!(action, subject, *args)
          authorize!(action, subject, *args)
        end

        def require_spree_current_user
          raise CanCan::AccessDenied if spree_current_user.nil?
        end

        # Needs to be overriden so that we use Spree's Ability rather than anyone else's.
        def current_ability
          @current_ability ||= Spree::Dependencies.ability_class.constantize.new(spree_current_user)
        end

        def request_includes
          # if API user want's to receive only the bare-minimum
          # the API will return only the main resource without any included
          if params[:include]&.blank?
            []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,12 @@
         end
 
         def spree_current_user
-          @spree_current_user ||= Spree.user_class.find_by(id: doorkeeper_token.resource_owner_id) if doorkeeper_token
+          return nil unless doorkeeper_token
+          return @spree_current_user if @spree_current_user
+
+          doorkeeper_authorize!
+
+          @spree_current_user ||= Spree.user_class.find_by(id: doorkeeper_token.resource_owner_id)
         end
 
         def spree_authorize!(action, subject, *args)
```
