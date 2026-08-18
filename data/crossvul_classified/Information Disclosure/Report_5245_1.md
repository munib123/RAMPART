# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 141-167 of the vulnerable file.

  private

  def find_resource(permission = :view_users)
    editing_self? ? User.find(User.current.id) : User.authorized(permission).except_hidden.find(params[:id])
  end

  def login_user(user)
    session[:user]         = user.id
    uri                    = session.to_hash.with_indifferent_access[:original_uri]
    session[:original_uri] = nil
    set_current_taxonomies(user, {:session => session})
    TopbarSweeper.expire_cache(self)
    redirect_to (uri || hosts_path)
  end

  def parameter_filter_context
    Foreman::Controller::Parameters::User::Context.new(:ui, controller_name, params[:action], editing_self?)
  end

  def verify_active_session
    if !request.post? && params[:status].blank? && User.exists?(session[:user].presence)
      warning _("You have already logged in")
      redirect_back_or_to hosts_path
      return
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,7 +158,7 @@
   end
 
   def verify_active_session
-    if !request.post? && params[:status].blank? && User.exists?(session[:user].presence)
+    if !request.post? && params[:status].blank? && User.unscoped.exists?(session[:user].presence)
       warning _("You have already logged in")
       redirect_back_or_to hosts_path
       return
```
