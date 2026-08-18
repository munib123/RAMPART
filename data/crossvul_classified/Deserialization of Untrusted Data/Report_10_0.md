# CrossVul Fix Pair: Deserialization of Untrusted Data in ruby
**Pair ID:** 10_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `10_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```ruby
Lines 47-87 of the vulnerable file.

    end
  end

  def execute
    @host = options[:host]

    sign_in
    name = get_one_gem_name

    add_owners    name, options[:add]
    remove_owners name, options[:remove]
    show_owners   name
  end

  def show_owners name
    response = rubygems_api_request :get, "api/v1/gems/#{name}/owners.yaml" do |request|
      request.add_field "Authorization", api_key
    end

    with_response response do |resp|
      owners = YAML.load resp.body

      say "Owners for gem: #{name}"
      owners.each do |owner|
        say "- #{owner['email'] || owner['handle'] || owner['id']}"
      end
    end
  end

  def add_owners name, owners
    manage_owners :post, name, owners
  end

  def remove_owners name, owners
    manage_owners :delete, name, owners
  end

  def manage_owners method, name, owners
    owners.each do |owner|
      begin
        response = rubygems_api_request method, "api/v1/gems/#{name}/owners" do |request|
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,7 @@
     end
 
     with_response response do |resp|
-      owners = YAML.load resp.body
+      owners = Gem::SafeYAML.load resp.body
 
       say "Owners for gem: #{name}"
       owners.each do |owner|
```
