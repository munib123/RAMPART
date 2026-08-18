# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 3528_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3528_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

class BuildController < ApplicationController

  def index
    valid_http_methods :get, :post, :put

    # for permission check
    if params[:package] and not ["_repository", "_jobhistory"].include?(params[:package])
      pkg = DbPackage.get_by_project_and_name( params[:project], params[:package], use_source=false )
    else
      prj = DbProject.get_by_name params[:project]
    end

    pass_to_backend 
  end

  def project_index
    valid_http_methods :get, :post, :put

    prj = nil
    unless params[:project] == "_dispatchprios"
      prj = DbProject.get_by_name params[:project]
    end

    if request.get?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 class BuildController < ApplicationController
 
   def index
-    valid_http_methods :get, :post, :put
+    valid_http_methods :get, :post
 
     # for permission check
     if params[:package] and not ["_repository", "_jobhistory"].include?(params[:package])
@@ -10,7 +10,19 @@
       prj = DbProject.get_by_name params[:project]
     end
 
-    pass_to_backend 
+    if request.get?
+      pass_to_backend 
+      return
+    end
+
+    if @http_user.is_admin?
+      # check for a local package instance
+      DbPackage.get_by_project_and_name( params[:project], params[:package], follow_project_links=false )
+      pass_to_backend
+    else
+      render_error :status => 403, :errorcode => "execute_cmd_no_permission",
+        :message => "Upload of binaries is only permitted for administrators"
+    end
   end
 
   def project_index
@@ -128,21 +140,6 @@
     pass_to_backend
   end
 
-  # /build/:prj/:repo/:arch/:pkg
-  def package_index
-    valid_http_methods :get
-    required_parameters :project, :repository, :arch, :package
-
-    # read access permission check
-    if params[:package] == "_repository"
-      prj = DbProject.get_by_name params[:project], use_source=false
-    else
-      pkg = DbPackage.get_by_project_and_name params[:project], params[:package], use_source=false
-    end
-
-    pass_to_backend
-  end
-
   # /build/:project/:repository/:arch/:package/:filename
   def file
     valid_http_methods :get, :delete
```
