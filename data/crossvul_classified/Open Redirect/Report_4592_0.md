# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in ruby
**Pair ID:** 4592_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4592_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```ruby
Lines 51-86 of the vulnerable file.

    session[session_member_key]["last_logged_in"] = timestamp if session[session_member_key]
  end

  def clear_member
    session[session_member_key] = nil if @cur_site
    @cur_member = nil
  end

  def member_login_node
    @member_login_node ||= begin
      node = Member::Node::Login.site(@cur_site).and_public.first
      node.present? ? node : false
    end
  end

  def member_login_path
    return false unless member_login_node
    "#{member_login_node.url}login.html"
  end

  def redirect_url
    return "/" unless member_login_node
    member_login_node.redirect_url || "/"
  end

  def translate_redirect_option(opts)
    case opts[:redirect]
    when true
      REDIRECT_OPTION_ENABLED
    when false
      REDIRECT_OPTION_DISABLED
    else
      REDIRECT_OPTION_UNDEFINED
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,11 +68,6 @@
     "#{member_login_node.url}login.html"
   end
 
-  def redirect_url
-    return "/" unless member_login_node
-    member_login_node.redirect_url || "/"
-  end
-
   def translate_redirect_option(opts)
     case opts[:redirect]
     when true
```
