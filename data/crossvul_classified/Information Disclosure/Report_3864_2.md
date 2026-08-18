# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3864_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3864_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 1-32 of the vulnerable file.

# frozen_string_literal: true

module Doorkeeper
  class AuthorizedApplicationsController < Doorkeeper::ApplicationController
    before_action :authenticate_resource_owner!

    def index
      @applications = Doorkeeper.config.application_model.authorized_for(current_resource_owner)

      respond_to do |format|
        format.html
        format.json { render json: @applications }
      end
    end

    def destroy
      Doorkeeper.config.application_model.revoke_tokens_and_grants_for(
        params[:id],
        current_resource_owner,
      )

      respond_to do |format|
        format.html do
          redirect_to oauth_authorized_applications_url, notice: I18n.t(
            :notice, scope: %i[doorkeeper flash authorized_applications destroy],
          )
        end

        format.json { render :no_content }
      end
    end
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
 
       respond_to do |format|
         format.html
-        format.json { render json: @applications }
+        format.json { render json: @applications, current_resource_owner: current_resource_owner }
       end
     end
 
```
