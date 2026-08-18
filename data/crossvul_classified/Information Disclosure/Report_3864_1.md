# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3864_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3864_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 2-42 of the vulnerable file.


module Doorkeeper
  class ApplicationsController < Doorkeeper::ApplicationController
    layout "doorkeeper/admin" unless Doorkeeper.configuration.api_only

    before_action :authenticate_admin!
    before_action :set_application, only: %i[show edit update destroy]

    def index
      @applications = Doorkeeper.config.application_model.ordered_by(:created_at)

      respond_to do |format|
        format.html
        format.json { head :no_content }
      end
    end

    def show
      respond_to do |format|
        format.html
        format.json { render json: @application }
      end
    end

    def new
      @application = Doorkeeper.config.application_model.new
    end

    def create
      @application = Doorkeeper.config.application_model.new(application_params)

      if @application.save
        flash[:notice] = I18n.t(:notice, scope: %i[doorkeeper flash applications create])
        flash[:application_secret] = @application.plaintext_secret

        respond_to do |format|
          format.html { redirect_to oauth_application_url(@application) }
          format.json { render json: @application }
        end
      else
        respond_to do |format|
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,7 +19,7 @@
     def show
       respond_to do |format|
         format.html
-        format.json { render json: @application }
+        format.json { render json: @application, as_owner: true }
       end
     end
 
@@ -36,7 +36,7 @@
 
         respond_to do |format|
           format.html { redirect_to oauth_application_url(@application) }
-          format.json { render json: @application }
+          format.json { render json: @application, as_owner: true }
         end
       else
         respond_to do |format|
@@ -58,7 +58,7 @@
 
         respond_to do |format|
           format.html { redirect_to oauth_application_url(@application) }
-          format.json { render json: @application }
+          format.json { render json: @application, as_owner: true }
         end
       else
         respond_to do |format|
```
