# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3561_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3561_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 32-78 of the vulnerable file.

    @list = Chef::ApiClient.cdb_list(true)
    display(@list.inject({}) { |result, element| result[element.name] = absolute_url(:client, :id => element.name); result })
  end

  # GET /clients/:id
  def show
    begin
      @client = Chef::ApiClient.cdb_load(params[:id])
    rescue Chef::Exceptions::CouchDBNotFound => e
      raise NotFound, "Cannot load client #{params[:id]}"
    end
    #display({ :name => @client.name, :admin => @client.admin, :public_key => @client.public_key })
    display @client
  end

  # POST /clients
  def create
    exists = true 
    if params.has_key?(:inflated_object)
      params[:name] ||= params[:inflated_object].name
      # We can only get here if we're admin or the validator. Only
      # allow creating admin clients if we're already an admin.
      if @auth_user.admin
        params[:admin] ||= params[:inflated_object].admin
      else
        params[:admin] = false
      end
    end

    begin
      Chef::ApiClient.cdb_load(params[:name])
    rescue Chef::Exceptions::CouchDBNotFound
      exists = false 
    end
    raise Conflict, "Client already exists" if exists

    @client = Chef::ApiClient.new
    @client.name(params[:name])
    @client.admin(params[:admin]) if params[:admin]
    @client.create_keys
    @client.cdb_save
    
    self.status = 201
    headers['Location'] = absolute_url(:client, @client.name)
    display({ :uri => absolute_url(:client, @client.name), :private_key => @client.private_key })
  end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,13 +49,13 @@
     exists = true 
     if params.has_key?(:inflated_object)
       params[:name] ||= params[:inflated_object].name
-      # We can only get here if we're admin or the validator. Only
-      # allow creating admin clients if we're already an admin.
-      if @auth_user.admin
-        params[:admin] ||= params[:inflated_object].admin
-      else
-        params[:admin] = false
-      end
+      params[:admin] ||= params[:inflated_object].admin
+    end
+
+    # We can only create clients if we're the admin or the validator.
+    # But only allow creating admin clients if we're already an admin.
+    if params[:admin] == true && @auth_user.admin != true
+      raise Forbidden, "You are not allowed to take this action."
     end
 
     begin
```
