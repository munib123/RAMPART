# CrossVul Fix Pair: Permission Issues in ruby
**Pair ID:** 5709_0
**Vulnerability Class:** Permission Issues
**CWE:** CWE-275
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5709_0`)

## Vulnerability Information & PoC

## Description
Permission Issues

## Vulnerable Code
```ruby
Lines 425-465 of the vulnerable file.

  rescue_from APIException do |exception|
    logger.debug "#{exception.class.name} #{exception.message}"
    message = exception.message
    if message.blank? || message == exception.class.name
      message = exception.default_message
    end
    render_error message: message, status: exception.status, errorcode: exception.errorcode
  end

  rescue_from Suse::Backend::HTTPError do |exception|
    xml = REXML::Document.new( exception.message )
    http_status = xml.root.attributes['code']
    unless xml.root.attributes.include? 'origin'
      xml.root.add_attribute "origin", "backend"
    end
    xml_text = String.new
    xml.write xml_text
    render :text => xml_text, :status => http_status
  end

  rescue_from Suse::Backend::NotFoundError, ActiveRecord::RecordNotFound do |exception|
    render_error message: exception.message, status: 404, errorcode: 'not_found'
  end

  def permissions
    return @user_permissions
  end

  def user
    return @http_user
  end

  def required_parameters(*parameters)
    parameters.each do |parameter|
      unless params.include? parameter.to_s
        raise MissingParameterError, "Required Parameter #{parameter} missing"
      end
    end
  end

  def valid_http_methods(*methods)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -442,6 +442,14 @@
     render :text => xml_text, :status => http_status
   end
 
+  rescue_from Project::WritePermissionError do |exception|
+    render_error :status => 403, :errorcode => "modify_project_no_permission", :message => exception.message
+  end
+
+  rescue_from Package::WritePermissionError do |exception|
+    render_error :status => 403, :errorcode => "modify_package_no_permission", :message => exception.message
+  end
+
   rescue_from Suse::Backend::NotFoundError, ActiveRecord::RecordNotFound do |exception|
     render_error message: exception.message, status: 404, errorcode: 'not_found'
   end
```
