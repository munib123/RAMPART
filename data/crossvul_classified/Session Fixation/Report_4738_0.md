# CrossVul Fix Pair: Session Fixation in ruby
**Pair ID:** 4738_0
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4738_0`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```ruby
Lines 128-168 of the vulnerable file.

      $logger.debug('Config files sync thread finished')
    }
    sleep(Cfgsync::ConfigSyncControl.sync_thread_interval())
  end
}

$thread_session_expired = Thread.new {
  while true
    sleep(60 * 5)
    begin
      if $session_storage
        $session_storage.drop_expired($session_storage_env)
      end
    rescue => e
      $logger.warn("Exception while removing expired sessions: #{e}")
    end
  end
}

helpers do
  def protected!
    gui_request = ( # these are URLs for web pages
      request.path == '/' or
      request.path == '/manage' or
      request.path == '/permissions' or
      request.path.match('/managec/.+/main')
    )
    if request.path.start_with?('/remote/') or request.path == '/run_pcs'
      @auth_user = PCSAuth.loginByToken(cookies)
      unless @auth_user
        halt [401, '{"notauthorized":"true"}']
      end
    else #/managec/* /manage/* /permissions
      if !gui_request and
        request.env['HTTP_X_REQUESTED_WITH'] != 'XMLHttpRequest'
      then
        # Accept non GUI requests only with header
        # "X_REQUESTED_WITH: XMLHttpRequest". (check if they are send via AJAX).
        # This prevents CSRF attack.
        halt [401, '{"notauthorized":"true"}']
      elsif not PCSAuth.isLoggedIn(session)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,6 +145,10 @@
 }
 
 helpers do
+  def is_ajax?
+    return request.env['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest'
+  end
+
   def protected!
     gui_request = ( # these are URLs for web pages
       request.path == '/' or
@@ -158,9 +162,7 @@
         halt [401, '{"notauthorized":"true"}']
       end
     else #/managec/* /manage/* /permissions
-      if !gui_request and
-        request.env['HTTP_X_REQUESTED_WITH'] != 'XMLHttpRequest'
-      then
+      if !gui_request and !is_ajax? then
         # Accept non GUI requests only with header
         # "X_REQUESTED_WITH: XMLHttpRequest". (check if they are send via AJAX).
         # This prevents CSRF attack.
@@ -361,9 +363,9 @@
 if not DISABLE_GUI
   get('/login'){ erb :login, :layout => :main }
 
-  get '/logout' do 
+  get '/logout' do
     session.destroy
-    erb :login, :layout => :main
+    redirect '/login'
   end
 
   post '/login' do
@@ -383,11 +385,19 @@
       #      end
       #      redirect plp
       #    else
-      redirect '/manage'
+      if is_ajax?
+        halt [200, "OK"]
+      else
+        redirect '/manage'
+      end
       #    end
     else
-      session["bad_login_name"] = params['username']
-      redirect '/login?badlogin=1'
+      if is_ajax?
+        halt [401, '{"notauthorized":"true"}']
+      else
+        session["bad_login_name"] = params['username']
+        redirect '/login?badlogin=1'
+      end
     end
   end
 
```
