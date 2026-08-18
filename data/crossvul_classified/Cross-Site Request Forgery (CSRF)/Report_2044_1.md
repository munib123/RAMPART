# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 2044_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2044_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 88-119 of the vulnerable file.


    config.assets.precompile +=
      %w( dataTables/back_disabled.png
          dataTables/back_enabled_hover.png
          dataTables/back_enabled.png
          dataTables/forward_disabled.png
          dataTables/forward_enabled_hover.png
          dataTables/forward_enabled.png
          dataTables/sort_asc_disabled.png
          dataTables/sort_asc.png
          dataTables/sort_both.png
          dataTables/sort_desc_disabled.png
          dataTables/sort_desc.png )

    config.action_controller.action_on_unpermitted_parameters = :raise

    config.action_dispatch.rescue_responses.merge!('ActiveXML::Transport::UnauthorizedError' => 401)
    config.action_dispatch.rescue_responses.merge!('ActiveXML::Transport::ConnectionError' => 503)
    config.action_dispatch.rescue_responses.merge!('ActiveXML::Transport::Error' => 500)
    config.action_dispatch.rescue_responses.merge!('Timeout::Error' => 408)

    # avoid a warning
    I18n.enforce_available_locales = true

    # we're not threadsafe
    config.allow_concurrency = false

    config.after_initialize do
      # See Rails::Configuration for more options
    end unless Rails.env.test?
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,6 +105,7 @@
     config.action_dispatch.rescue_responses.merge!('ActiveXML::Transport::ConnectionError' => 503)
     config.action_dispatch.rescue_responses.merge!('ActiveXML::Transport::Error' => 500)
     config.action_dispatch.rescue_responses.merge!('Timeout::Error' => 408)
+    config.action_dispatch.rescue_responses.merge!('ActionController::InvalidAuthenticityToken' => 403)
 
     # avoid a warning
     I18n.enforce_available_locales = true
```
