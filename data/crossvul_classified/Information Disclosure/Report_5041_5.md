# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5041_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5041_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 132-172 of the vulnerable file.

      rack_file.call(resources_env)
    end


    def current
      MiniProfiler.current
    end

    def current=(c)
      MiniProfiler.current = c
    end


    def config
      @config
    end


    def call(env)

      client_settings = ClientSettings.new(env)

      status = headers = body = nil
      query_string = env['QUERY_STRING']
      path         = env['PATH_INFO'].sub('//', '/')

      # Someone (e.g. Rails engine) could change the SCRIPT_NAME so we save it
      env['RACK_MINI_PROFILER_ORIGINAL_SCRIPT_NAME'] = env['SCRIPT_NAME']

      skip_it = (@config.pre_authorize_cb && !@config.pre_authorize_cb.call(env)) ||
                (@config.skip_paths && @config.skip_paths.any?{ |p| path.start_with?(p) }) ||
                query_string =~ /pp=skip/

      has_profiling_cookie = client_settings.has_cookie?

      if skip_it || (@config.authorization_mode == :whitelist && !has_profiling_cookie)
        status,headers,body = @app.call(env)
        if !skip_it && @config.authorization_mode == :whitelist && !has_profiling_cookie && MiniProfiler.request_authorized?
          client_settings.write!(headers)
        end
        return [status,headers,body]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -149,7 +149,9 @@
 
     def call(env)
 
-      client_settings = ClientSettings.new(env)
+      start = Time.now
+      client_settings = ClientSettings.new(env, @storage, start)
+      MiniProfiler.deauthorize_request if @config.authorization_mode == :whitelist
 
       status = headers = body = nil
       query_string = env['QUERY_STRING']
@@ -162,18 +164,15 @@
                 (@config.skip_paths && @config.skip_paths.any?{ |p| path.start_with?(p) }) ||
                 query_string =~ /pp=skip/
 
-      has_profiling_cookie = client_settings.has_cookie?
-
-      if skip_it || (@config.authorization_mode == :whitelist && !has_profiling_cookie)
-        status,headers,body = @app.call(env)
-        if !skip_it && @config.authorization_mode == :whitelist && !has_profiling_cookie && MiniProfiler.request_authorized?
-          client_settings.write!(headers)
-        end
-        return [status,headers,body]
+      if skip_it || (
+        @config.authorization_mode == :whitelist &&
+        !client_settings.has_valid_cookie?
+      )
+        return client_settings.handle_cookie(@app.call(env))
       end
 
       # handle all /mini-profiler requests here
-      return serve_html(env) if path.start_with? @config.base_url_path
+      return client_settings.handle_cookie(serve_html(env)) if path.start_with? @config.base_url_path
 
       has_disable_cookie = client_settings.disable_profiling?
       # manual session disable / enable
@@ -181,7 +180,7 @@
         skip_it = true
       end
 
-      if query_string =~ /pp=enable/ && (@config.authorization_mode != :whitelist || MiniProfiler.request_authorized?)
+      if query_string =~ /pp=enable/
         skip_it = false
         config.enabled = true
       end
@@ -189,8 +188,7 @@
       if skip_it || !config.enabled
         status,headers,body = @app.call(env)
         client_settings.disable_profiling = true
-        client_settings.write!(headers)
-        return [status,headers,body]
+        return client_settings.handle_cookie([status,headers,body])
       else
         client_settings.disable_profiling = false
       end
@@ -198,7 +196,7 @@
       # profile gc
       if query_string =~ /pp=profile-gc/
         current.measure = false if current
-        return Rack::MiniProfiler::GCProfiler.new.profile_gc(@app, env)
+        return client_settings.handle_cookie(Rack::MiniProfiler::GCProfiler.new.profile_gc(@app, env))
       end
 
       # profile memory
@@ -215,11 +213,10 @@
           body.close if body.respond_to? :close
         end
         report.pretty_print(result)
-        return text_result(result.string)
+        return client_settings.handle_cookie(text_result(result.string))
       end
 
       MiniProfiler.create_current(env, @config)
-      MiniProfiler.deauthorize_request if @config.authorization_mode == :whitelist
 
       if query_string =~ /pp=normal-backtrace/
         client_settings.backtrace_level = ClientSettings::BACKTRACE_DEFAULT
@@ -238,7 +235,6 @@
       trace_exceptions = query_string =~ /pp=trace-exceptions/ && defined? TracePoint
       status, headers, body, exceptions,trace = nil
 
-      start = Time.now
 
       if trace_exceptions
         exceptions = []
@@ -281,7 +277,6 @@
         else
           status,headers,body = @app.call(env)
         end
-        client_settings.write!(headers)
       ensure
         trace.disable if trace
       end
@@ -289,35 +284,30 @@
       skip_it = current.discard
 
       if (config.authorization_mode == :whitelist && !MiniProfiler.request_authorized?)
-        # this is non-obvious, don't kill the profiling cookie on errors or short requests
-        # this ensures that stuff that never reaches the rails stack does not kill profiling
-        if status.to_i >= 200 && status.to_i < 300 && ((Time.now - start) > 0.1)
-          client_settings.discard_cookie!(headers)
-        end
         skip_it = true
       end
 
-      return [status,headers,body] if skip_it
+      return client_settings.handle_cookie([status,headers,body]) if skip_it
 
       # we must do this here, otherwise current[:discard] is not being properly treated
       if trace_exceptions
         body.close if body.respond_to? :close
-        return dump_exceptions exceptions
+        return client_settings.handle_cookie(dump_exceptions exceptions)
       end
 
       if query_string =~ /pp=env/ && !config.disable_env_dump
         body.close if body.respond_to? :close
-        return dump_env env
+        return client_settings.handle_cookie(dump_env env)
       end
 
       if query_string =~ /pp=analyze-memory/
         body.close if body.respond_to? :close
-        return analyze_memory
+        return client_settings.handle_cookie(analyze_memory)
       end
 
       if query_string =~ /pp=help/
         body.close if body.respond_to? :close
-        return help(client_settings, env)
+        return client_settings.handle_cookie(help(client_settings, env))
       end
 
       page_struct = current.page_struct
@@ -326,7 +316,7 @@
 
       if flamegraph
         body.close if body.respond_to? :close
-        return self.flamegraph(flamegraph)
+        return client_settings.handle_cookie(self.flamegraph(flamegraph))
       end
 
 
@@ -337,9 +327,8 @@
 
         # inject headers, script
         if status >= 200 && status < 300
-          client_settings.write!(headers)
           result = inject_profiler(env,status,headers,body)
-          return result if result
+          return client_settings.handle_cookie(result) if result
         end
       rescue Exception => e
         if @config.storage_failure != nil
@@ -347,8 +336,7 @@
         end
       end
 
-      client_settings.write!(headers)
-      [status, headers, body]
+      client_settings.handle_cookie([status, headers, body])
 
     ensure
       # Make sure this always happens
@@ -543,7 +531,6 @@
 </html>
 "
 
-      client_settings.write!(headers)
       [200, headers, [body]]
     end
 
```
