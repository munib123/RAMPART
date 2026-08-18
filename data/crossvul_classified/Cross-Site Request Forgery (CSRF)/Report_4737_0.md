# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 4737_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4737_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 104-150 of the vulnerable file.

              PCSAuth.getSuperuserSession(), Cfgsync::get_cfg_classes(),
              get_corosync_nodes(), cluster_name
            )
            cfgs_to_save, _ = fetcher.fetch()
            cfgs_to_save.each { |cfg_to_save|
              cfg_to_save.save()
            }
          end
        rescue => e
          $logger.warn("Config files sync thread exception: #{e}")
        end
      end
      $logger.debug('Config files sync thread finished')
    }
    sleep(Cfgsync::ConfigSyncControl.sync_thread_interval())
  end
}

helpers do
  def protected!
    if not PCSAuth.loginByToken(session, cookies) and not PCSAuth.isLoggedIn(session)
      # If we're on /managec/<cluster_name>/main we redirect
      match_expr = "/managec/(.*)/(.*)"
      mymatch = request.path.match(match_expr)
      on_managec_main = false
      if mymatch and mymatch.length >= 3 and mymatch[2] == "main"
        on_managec_main = true
      end

      if request.path.start_with?('/remote') or
        (request.path.match(match_expr) and not on_managec_main) or
        '/run_pcs' == request.path or
        '/clusters_overview' == request.path or
        request.path.start_with?('/permissions_')
      then
        $logger.info "ERROR: Request without authentication"
        halt [401, '{"notauthorized":"true"}']
      else
        session[:pre_login_path] = request.path
        redirect '/login'
      end
    end
  end

  def getParamList(params)
    param_line = []
    meta_options = []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,26 +121,31 @@
 
 helpers do
   def protected!
-    if not PCSAuth.loginByToken(session, cookies) and not PCSAuth.isLoggedIn(session)
-      # If we're on /managec/<cluster_name>/main we redirect
-      match_expr = "/managec/(.*)/(.*)"
-      mymatch = request.path.match(match_expr)
-      on_managec_main = false
-      if mymatch and mymatch.length >= 3 and mymatch[2] == "main"
-        on_managec_main = true
-      end
-
-      if request.path.start_with?('/remote') or
-        (request.path.match(match_expr) and not on_managec_main) or
-        '/run_pcs' == request.path or
-        '/clusters_overview' == request.path or
-        request.path.start_with?('/permissions_')
+    gui_request = ( # these are URLs for web pages
+      request.path == '/' or
+      request.path == '/manage' or
+      request.path == '/permissions' or
+      request.path.match('/managec/.+/main')
+    )
+    if request.path.start_with?('/remote/') or request.path == '/run_pcs'
+      unless PCSAuth.loginByToken(session, cookies)
+        halt [401, '{"notauthorized":"true"}']
+      end
+    else #/managec/* /manage/* /permissions
+      if !gui_request and
+        request.env['HTTP_X_REQUESTED_WITH'] != 'XMLHttpRequest'
       then
-        $logger.info "ERROR: Request without authentication"
+        # Accept non GUI requests only with header
+        # "X_REQUESTED_WITH: XMLHttpRequest". (check if they are send via AJAX).
+        # This prevents CSRF attack.
         halt [401, '{"notauthorized":"true"}']
-      else
-        session[:pre_login_path] = request.path
-        redirect '/login'
+      elsif not PCSAuth.isLoggedIn(session)
+        if gui_request
+          session[:pre_login_path] = request.path
+          redirect '/login'
+        else
+          halt [401, '{"notauthorized":"true"}']
+        end
       end
     end
   end
```
