# CrossVul Fix Pair: Session Fixation in ruby
**Pair ID:** 4739_0
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4739_0`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```ruby
Lines 30-70 of the vulnerable file.

        password_file = File.open($user_pass_file, File::RDWR|File::CREAT)
        password_file.flock(File::LOCK_EX)
        json = password_file.read()
        users = JSON.parse(json)
      rescue Exception
        $logger.info "Empty pcs_users.conf file, creating new file"
        users = []
      end
      users << {"username" => username, "token" => token, "creation_date" => Time.now}
      password_file.truncate(0)
      password_file.rewind
      password_file.write(JSON.pretty_generate(users))
      password_file.close()
      return token
    end
    return true
  end

  def self.getUsersGroups(username)
    stdout, stderr, retval = run_cmd(
      getSuperuserSession, "id", "-Gn", username
    )
    if retval != 0
      $logger.info(
        "Unable to determine groups of user '#{username}': #{stderr.join(' ').strip}"
      )
      return [false, []]
    end
    return [true, stdout.join(' ').split(nil)]
  end

  def self.isUserAllowedToLogin(username, log_success=true)
    success, groups = getUsersGroups(username)
    if not success
      $logger.info(
        "Failed login by '#{username}' (unable to determine user's groups)"
      )
      return false
    end
    if not groups.include?(ADMIN_GROUP)
      $logger.info(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,7 +47,7 @@
 
   def self.getUsersGroups(username)
     stdout, stderr, retval = run_cmd(
-      getSuperuserSession, "id", "-Gn", username
+      getSuperuserAuth(), "id", "-Gn", username
     )
     if retval != 0
       $logger.info(
@@ -94,41 +94,43 @@
     return false
   end
 
-  def self.loginByToken(session, cookies)
+  def self.loginByToken(cookies)
+    auth_user = {}
     if username = validToken(cookies["token"])
       if SUPERUSER == username
         if cookies['CIB_user'] and cookies['CIB_user'].strip != ''
-          session[:username] = cookies['CIB_user']
+          auth_user[:username] = cookies['CIB_user']
           if cookies['CIB_user_groups'] and cookies['CIB_user_groups'].strip != ''
-            session[:usergroups] = cookieUserDecode(
+            auth_user[:usergroups] = cookieUserDecode(
               cookies['CIB_user_groups']
             ).split(nil)
           else
-            session[:usergroups] = []
+            auth_user[:usergroups] = []
           end
         else
-          session[:username] = SUPERUSER
-          session[:usergroups] = []
+          auth_user[:username] = SUPERUSER
+          auth_user[:usergroups] = []
         end
-        return true
+        return auth_user
       else
-        session[:username] = username
+        auth_user[:username] = username
         success, groups = getUsersGroups(username)
-        session[:usergroups] = success ? groups : []
-        return true
+        auth_user[:usergroups] = success ? groups : []
+        return auth_user
       end
     end
-    return false
+    return nil
   end
 
-  def self.loginByPassword(session, username, password)
+  def self.loginByPassword(username, password)
     if validUser(username, password)
-      session[:username] = username
+      auth_user = {}
+      auth_user[:username] = username
       success, groups = getUsersGroups(username)
-      session[:usergroups] = success ? groups : []
-      return true
+      auth_user[:usergroups] = success ? groups : []
+      return auth_user
     end
-    return false
+    return nil
   end
 
   def self.isLoggedIn(session)
@@ -141,7 +143,7 @@
     return false
   end
 
-  def self.getSuperuserSession()
+  def self.getSuperuserAuth()
     return {
       :username => SUPERUSER,
       :usergroups => [],
@@ -162,5 +164,17 @@
   def self.cookieUserDecode(text)
     return Base64.decode64(text)
   end
+
+  def self.sessionToAuthUser(session)
+    return {
+      :username => session[:username],
+      :usergroups => session[:usergroups],
+    }
+  end
+
+  def self.authUserToSession(auth_user, session)
+    session[:username] = auth_user[:username]
+    session[:usergroups] = auth_user[:usergroups]
+  end
 end
 
```
