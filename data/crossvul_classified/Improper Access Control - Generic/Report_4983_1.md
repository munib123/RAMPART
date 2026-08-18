# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 4983_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4983_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 86-127 of the vulnerable file.

      raise ArgumentError, "The environment must be purely alphanumeric, not '#{environment}'"
    end

    configured_environment = Puppet.lookup(:environments).get(environment)
    unless configured_environment.nil?
      configured_environment = configured_environment.override_from_commandline(Puppet.settings)
      params[:environment] = configured_environment
    end

    check_authorization(method, "#{url_prefix}/#{indirection_name}/#{key}", params)

    if configured_environment.nil?
      raise ArgumentError, "Could not find environment '#{environment}'"
    end

    params.delete(:bucket_path)

    if key == "" or key.nil?
      raise ArgumentError, "No request key specified in #{uri}"
    end

    key = URI.unescape(key)

    [indirection, method, key, params]
  end

  private

  def do_http_control_exception(response, exception)
    msg = exception.message
    Puppet.info(msg)
    response.respond_with(exception.status, "text/plain", msg)
  end

  def do_exception(response, exception, status=400)
    if exception.is_a?(Puppet::Network::AuthorizationError)
      # make sure we return the correct status code
      # for authorization issues
      status = 403 if status == 400
    end

    Puppet.log_exception(exception)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,8 +104,6 @@
       raise ArgumentError, "No request key specified in #{uri}"
     end
 
-    key = URI.unescape(key)
-
     [indirection, method, key, params]
   end
 
```
