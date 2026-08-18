# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in ruby
**Pair ID:** 4592_2
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4592_2`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```ruby
Lines 5-45 of the vulnerable file.

    default_scope ->{ where(route: /^member\//) }
  end

  class Login
    include Cms::Model::Node
    include Cms::Addon::NodeSetting
    include Cms::Addon::Meta
    include Member::Addon::Redirection
    include Member::Addon::FormAuth
    include Member::Addon::TwitterOauth
    include Member::Addon::FacebookOauth
    include Member::Addon::YahooJpOauth
    include Member::Addon::YahooJpOauthV2
    include Member::Addon::GoogleOauth
    include Member::Addon::GithubOauth
    include Cms::Addon::Release
    include Cms::Addon::GroupPermission
    include History::Addon::Backup

    default_scope ->{ where(route: "member/login") }
  end

  class Mypage
    include Cms::Model::Node
    include Cms::Addon::NodeSetting
    include Cms::Addon::Meta
    include Cms::Addon::Html
    include Cms::Addon::Release
    include Cms::Addon::GroupPermission
    include History::Addon::Backup

    default_scope ->{ where(route: "member/mypage") }

    def children
      Member::Node::Base.and_public.
        where(site_id: site_id, filename: /^#{::Regexp.escape(filename)}\//, depth: depth + 1).
        order_by(order: 1)
    end
  end

  class MyProfile
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,45 @@
     include History::Addon::Backup
 
     default_scope ->{ where(route: "member/login") }
+
+    def redirect_full_url
+      return if redirect_url.blank?
+
+      ret = make_full_url(redirect_url)
+      return if ret.blank?
+      return unless trusted?(ret)
+
+      ret.to_s
+    end
+
+    def make_trusted_full_url(ref)
+      return if ref.blank?
+
+      full_url = make_full_url(URI::decode(ref))
+      return if full_url.blank?
+
+      # normalize full url
+      full_url.fragment = nil
+      full_url.query = nil
+
+      # trusted?
+      return unless trusted?(full_url)
+
+      full_url.to_s
+    end
+
+    private
+
+    def make_full_url(path)
+      site_root_url = URI.parse(site.full_root_url)
+      URI.join(site_root_url, path) rescue nil
+    end
+
+    def trusted?(full_url)
+      return false if full_url.blank?
+
+      %w(http https).include?(full_url.scheme) && full_url.to_s.start_with?(site.full_url)
+    end
   end
 
   class Mypage
```
