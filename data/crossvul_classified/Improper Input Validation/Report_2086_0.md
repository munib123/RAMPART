# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 2086_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2086_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 362-402 of the vulnerable file.

      @project = nil
      render_404
      false
    end
  end

  def back_url
    url = params[:back_url]
    if url.nil? && referer = request.env['HTTP_REFERER']
      url = CGI.unescape(referer.to_s)
    end
    url
  end

  def redirect_back_or_default(default, options={})
    back_url = params[:back_url].to_s
    if back_url.present?
      begin
        uri = URI.parse(back_url)
        # do not redirect user to another host or to the login or register page
        if (uri.relative? || (uri.host == request.host)) && !uri.path.match(%r{/(login|account/register)})
          redirect_to(back_url)
          return
        end
      rescue URI::InvalidURIError
        logger.warn("Could not redirect to invalid URL #{back_url}")
        # redirect to default
      end
    elsif options[:referer]
      redirect_to_referer_or default
      return
    end
    redirect_to default
    false
  end

  # Redirects to the request referer if present, redirects to args or call block otherwise.
  def redirect_to_referer_or(*args, &block)
    redirect_to :back
  rescue ::ActionController::RedirectBackError
    if args.any?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -379,7 +379,7 @@
       begin
         uri = URI.parse(back_url)
         # do not redirect user to another host or to the login or register page
-        if (uri.relative? || (uri.host == request.host)) && !uri.path.match(%r{/(login|account/register)})
+        if ((uri.relative? && back_url.match(%r{\A/\w})) || (uri.host == request.host)) && !uri.path.match(%r{/(login|account/register)})
           redirect_to(back_url)
           return
         end
```
