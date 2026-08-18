# CrossVul Fix Pair: Session Fixation in ruby
**Pair ID:** 4740_1
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4740_1`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```ruby
Lines 2-42 of the vulnerable file.

require 'sinatra/reloader' if development?
require 'sinatra/cookies'
require 'rexml/document'
require 'webrick'
require 'webrick/https'
require 'openssl'
require 'logger'
require 'thread'

require 'bootstrap.rb'
require 'resource.rb'
require 'remote.rb'
require 'fenceagent.rb'
require 'cluster.rb'
require 'config.rb'
require 'pcs.rb'
require 'auth.rb'
require 'wizard.rb'
require 'cfgsync.rb'
require 'permissions.rb'

Dir["wizards/*.rb"].each {|file| require file}

use Rack::CommonLogger

set :app_file, __FILE__

def generate_cookie_secret
  return SecureRandom.hex(30)
end

begin
  secret = File.read(COOKIE_FILE)
  secret_errors = verify_cookie_secret(secret)
  if secret_errors and not secret_errors.empty?
    secret_errors.each { |err| $logger.error err }
    $logger.error "Invalid cookie secret, using temporary one"
    secret = generate_cookie_secret()
  end
rescue Errno::ENOENT
  secret = generate_cookie_secret()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 require 'wizard.rb'
 require 'cfgsync.rb'
 require 'permissions.rb'
+require 'session.rb'
 
 Dir["wizards/*.rb"].each {|file| require file}
 
@@ -43,11 +44,18 @@
   File.open(COOKIE_FILE, 'w', 0700) {|f| f.write(secret)}
 end
 
-use Rack::Session::Cookie,
-  :expire_after => 60 * 60,
+session_lifetime = ENV['SESSION_LIFETIME'].to_i()
+session_lifetime = 60 * 60 unless session_lifetime > 0
+use SessionPoolLifetime,
+  :expire_after => session_lifetime,
   :secret => secret,
   :secure => true, # only send over HTTPS
   :httponly => true # don't provide to javascript
+
+# session storage instance
+# will be created by Rack later and fetched in "before" filter
+$session_storage = nil
+$session_storage_env = {}
 
 #use Rack::SSL
 
@@ -66,6 +74,13 @@
 
 before do
   @auth_user = nil
+
+  # get session storage instance from env
+  if not $session_storage and env[:__session_storage]
+    $session_storage = env[:__session_storage]
+    $session_storage_env = env
+  end
+
   if request.path != '/login' and not request.path == "/logout" and not request.path == '/remote/auth'
     protected! 
   end
@@ -116,6 +131,19 @@
   end
 }
 
+$thread_session_expired = Thread.new {
+  while true
+    sleep(60 * 5)
+    begin
+      if $session_storage
+        $session_storage.drop_expired($session_storage_env)
+      end
+    rescue => e
+      $logger.warn("Exception while removing expired sessions: #{e}")
+    end
+  end
+}
+
 helpers do
   def protected!
     gui_request = ( # these are URLs for web pages
@@ -334,7 +362,7 @@
   get('/login'){ erb :login, :layout => :main }
 
   get '/logout' do 
-    session.clear
+    session.destroy
     erb :login, :layout => :main
   end
 
```
