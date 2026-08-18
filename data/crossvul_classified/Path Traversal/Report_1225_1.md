# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 1225_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1225_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 47-87 of the vulnerable file.

      end
    end

    def debug?
      @debug_mode
    end

    def allow(&block)
      all_resources << (resources = Resources.new)

      if block.arity == 1
        block.call(resources)
      else
        resources.instance_eval(&block)
      end
    end

    def call(env)
      env[HTTP_ORIGIN] ||= env[HTTP_X_ORIGIN] if env[HTTP_X_ORIGIN]

      add_headers = nil
      if env[HTTP_ORIGIN]
        debug(env) do
          [ 'Incoming Headers:',
            "  Origin: #{env[HTTP_ORIGIN]}",
            "  Access-Control-Request-Method: #{env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]}",
            "  Access-Control-Request-Headers: #{env[HTTP_ACCESS_CONTROL_REQUEST_HEADERS]}"
            ].join("\n")
        end
        if env[REQUEST_METHOD] == OPTIONS and env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]
          headers = process_preflight(env)
          debug(env) do
            "Preflight Headers:\n" +
                headers.collect{|kv| "  #{kv.join(': ')}"}.join("\n")
          end
          return [200, headers, []]
        else
          add_headers = process_cors(env)
        end
      else
        Result.miss(env, Result::MISS_NO_ORIGIN)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,25 +63,28 @@
 
     def call(env)
       env[HTTP_ORIGIN] ||= env[HTTP_X_ORIGIN] if env[HTTP_X_ORIGIN]
+
+      path = evaluate_path(env)
 
       add_headers = nil
       if env[HTTP_ORIGIN]
         debug(env) do
           [ 'Incoming Headers:',
             "  Origin: #{env[HTTP_ORIGIN]}",
+            "  Path-Info: #{path}",
             "  Access-Control-Request-Method: #{env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]}",
             "  Access-Control-Request-Headers: #{env[HTTP_ACCESS_CONTROL_REQUEST_HEADERS]}"
             ].join("\n")
         end
         if env[REQUEST_METHOD] == OPTIONS and env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]
-          headers = process_preflight(env)
+          headers = process_preflight(env, path)
           debug(env) do
             "Preflight Headers:\n" +
                 headers.collect{|kv| "  #{kv.join(': ')}"}.join("\n")
           end
           return [200, headers, []]
         else
-          add_headers = process_cors(env)
+          add_headers = process_cors(env, path)
         end
       else
         Result.miss(env, Result::MISS_NO_ORIGIN)
@@ -90,7 +93,7 @@
       # This call must be done BEFORE calling the app because for some reason
       # env[PATH_INFO] gets changed after that and it won't match. (At least
       # in rails 4.1.6)
-      vary_resource = resource_for_path(env[PATH_INFO])
+      vary_resource = resource_for_path(path)
 
       status, headers, body = @app.call env
 
@@ -147,14 +150,20 @@
         end
       end
 
+      def evaluate_path(env)
+        path = env[PATH_INFO]
+        path = Rack::Utils.clean_path_info(Rack::Utils.unescape_path(path)) if path
+        path
+      end
+
       def all_resources
         @all_resources ||= []
       end
 
-      def process_preflight(env)
+      def process_preflight(env, path)
         result = Result.preflight(env)
 
-        resource, error = match_resource(env)
+        resource, error = match_resource(path, env)
         unless resource
           result.miss(error)
           return {}
@@ -163,8 +172,8 @@
         return resource.process_preflight(env, result)
       end
 
-      def process_cors(env)
-        resource, error = match_resource(env)
+      def process_cors(env, path)
+        resource, error = match_resource(path, env)
         if resource
           Result.hit(env)
           cors = resource.to_headers(env)
@@ -185,8 +194,7 @@
         nil
       end
 
-      def match_resource(env)
-        path   = env[PATH_INFO]
+      def match_resource(path, env)
         origin = env[HTTP_ORIGIN]
 
         origin_matched = false
```
