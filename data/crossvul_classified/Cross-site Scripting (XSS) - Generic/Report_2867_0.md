# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 2867_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2867_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 184-224 of the vulnerable file.

      link_options = {
          :title => l(:label_sort_by, "\"#{column.caption}\""),
          :class => css
        }
      if options[:sort_link_options]
        link_options.merge! options[:sort_link_options]
      end
      content = link_to(column.caption,
          {:params => request.query_parameters.deep_merge(sort_param)},
          link_options
        )
    else
      content = column.caption
    end
    content_tag('th', content)
  end

  def column_content(column, item)
    value = column.value_object(item)
    if value.is_a?(Array)
      value.collect {|v| column_value(column, item, v)}.compact.join(', ').html_safe
    else
      column_value(column, item, value)
    end
  end

  def column_value(column, item, value)
    case column.name
    when :id
      link_to value, issue_path(item)
    when :subject
      link_to value, issue_path(item)
    when :parent
      value ? (value.visible? ? link_to_issue(value, :subject => false) : "##{value.id}") : ''
    when :description
      item.description? ? content_tag('div', textilizable(item, :description), :class => "wiki") : ''
    when :last_notes
      item.last_notes.present? ? content_tag('div', textilizable(item, :last_notes), :class => "wiki") : ''
    when :done_ratio
      progress_bar(value)
    when :relations
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,7 +201,8 @@
   def column_content(column, item)
     value = column.value_object(item)
     if value.is_a?(Array)
-      value.collect {|v| column_value(column, item, v)}.compact.join(', ').html_safe
+      values = value.collect {|v| column_value(column, item, v)}.compact
+      safe_join(values, ', ')
     else
       column_value(column, item, value)
     end
```
