# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 2866_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2866_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 160-200 of the vulnerable file.

      h(project.name)
    else
      link_to project.name, project_path(project, options), html_options
    end
  end

  # Generates a link to a version
  def link_to_version(version, options = {})
    return '' unless version && version.is_a?(Version)
    options = {:title => format_date(version.effective_date)}.merge(options)
    link_to_if version.visible?, format_version_name(version), version_path(version), options
  end

  # Helper that formats object for html or text rendering
  def format_object(object, html=true, &block)
    if block_given?
      object = yield object
    end
    case object.class.name
    when 'Array'
      object.map {|o| format_object(o, html)}.join(', ').html_safe
    when 'Time'
      format_time(object)
    when 'Date'
      format_date(object)
    when 'Fixnum'
      object.to_s
    when 'Float'
      sprintf "%.2f", object
    when 'User'
      html ? link_to_user(object) : object.to_s
    when 'Project'
      html ? link_to_project(object) : object.to_s
    when 'Version'
      html ? link_to_version(object) : object.to_s
    when 'TrueClass'
      l(:general_text_Yes)
    when 'FalseClass'
      l(:general_text_No)
    when 'Issue'
      object.visible? && html ? link_to_issue(object) : "##{object.id}"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,7 +177,8 @@
     end
     case object.class.name
     when 'Array'
-      object.map {|o| format_object(o, html)}.join(', ').html_safe
+      formatted_objects = object.map {|o| format_object(o, html)}
+      html ? safe_join(formatted_objects, ', ') : formatted_objects.join(', ')
     when 'Time'
       format_time(object)
     when 'Date'
```
