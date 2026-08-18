# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in ruby
**Pair ID:** 1400_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1400_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```ruby
Lines 5-45 of the vulnerable file.

    protect_from_forgery except: :remote_login
    skip_before_action :verify_authenticity_token unless SS.config.env.protect_csrf
    prepend_view_path "app/views/sns/login"
    layout "ss/login"
    navi_view nil
  end

  private

  def remote_login?
    SS::config.sns.remote_login
  end

  def default_logged_in_path
    SS.config.sns.logged_in_page
  end

  def login_success
    if params[:ref].blank?
      redirect_to default_logged_in_path
    elsif params[:ref] =~ /^\//
      redirect_to params[:ref]
    else
      render "sns/login/redirect"
    end
  end

  def render_login(user, email_or_uid, opts = {})
    alert = opts.delete(:alert).presence || t("sns.errors.invalid_login")

    if user
      opts[:session] ||= true
      set_user user, opts

      respond_to do |format|
        format.html { login_success }
        format.json { head :no_content }
      end
    else
      @item = user_class.new
      @item.email = email_or_uid if email_or_uid.present?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
   def login_success
     if params[:ref].blank?
       redirect_to default_logged_in_path
-    elsif params[:ref] =~ /^\//
+    elsif params[:ref] =~ /^\/[^\/]/
       redirect_to params[:ref]
     else
       render "sns/login/redirect"
```
