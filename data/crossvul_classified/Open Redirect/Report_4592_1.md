# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in ruby
**Pair ID:** 4592_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4592_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```ruby
Lines 4-45 of the vulnerable file.


  skip_before_action :logged_in?, only: [:login, :logout, :callback, :failure]

  private

  def get_params
    params.require(:item).permit(:email, :password)
  rescue
    raise "400"
  end

  def set_member_and_redirect(member)
    set_member member
    Member::ActivityLog.create(
      cur_site: @cur_site,
      cur_member: member,
      activity_type: "login",
      remote_addr: remote_addr,
      user_agent: request.user_agent)

    ref = URI::decode(params[:ref] || flash[:ref] || "")
    ref = redirect_url if ref.blank?
    flash.discard(:ref)

    redirect_to ref
  end

  public

  def login
    @item = Cms::Member.new
    unless request.post?
      @error = flash[:alert]
      flash[:ref] = params[:ref]
      return
    end

    @item.attributes = get_params
    member = Cms::Member.site(@cur_site).and_enabled.where(email: @item.email, password: SS::Crypt.crypt(@item.password)).first
    unless member
      @error = t "sns.errors.invalid_login"
      return
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,11 +21,34 @@
       remote_addr: remote_addr,
       user_agent: request.user_agent)
 
-    ref = URI::decode(params[:ref] || flash[:ref] || "")
-    ref = redirect_url if ref.blank?
+    ref = @cur_node.make_trusted_full_url(params[:ref] || flash[:ref])
+    ref = @cur_node.redirect_full_url if ref.blank?
+    ref = @cur_site.full_url if ref.blank?
     flash.discard(:ref)
 
     redirect_to ref
+  end
+
+  def make_url_if_trusted(ref)
+    return if ref.blank?
+
+    ref = URI::decode(ref)
+
+    site_url = URI.parse(@cur_site.full_url)
+    full_url = URI.join(site_url, ref) rescue nil
+    return if full_url.blank?
+    return unless %w(http https).include?(full_url.scheme)
+
+    # normalize full url
+    full_url.fragment = nil
+    full_url.query = nil
+
+    # trusted?
+    return if full_url.scheme != site_url.scheme
+    return if full_url.host != site_url.host
+    return if full_url.port != site_url.port
+
+    full_url.to_s
   end
 
   public
```
