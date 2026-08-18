# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 5207_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5207_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 266-306 of the vulnerable file.


  def help_inline(inline, error)
    help_inline = error.empty? ? inline : content_tag(:span, error.to_sentence.html_safe, :class => 'error-message')
    case help_inline
      when blank?
        ""
      when :indicator
        content_tag(:span, content_tag(:div, '', :class => 'hide spinner spinner-xs'),
                    :class => 'help-block').html_safe
      else
        content_tag(:span, help_inline, :class => "help-block help-inline")
    end
  end

  def add_label options, f, attr
    label_size = options.delete(:label_size) || "col-md-2"
    required_mark = check_required(options, f, attr)
    label = options[:label] == :none ? '' : options.delete(:label)
    label ||= ((clazz = f.object.class).respond_to?(:gettext_translation_for_attribute_name) &&
        s_(clazz.gettext_translation_for_attribute_name attr)) if f
    label = label.present? ? label_tag(attr, "#{label}#{required_mark}".html_safe, :class => label_size + " control-label") : ''
    label
  end

  def check_required options, f, attr
    required = options.delete(:required) # we don't want to use html5 required attr so we delete the option
    return ' *' if required.nil? ? is_required?(f, attr) : required
  end

  def blank_or_inherit_f(f, attr)
    return true unless f.object.respond_to?(:parent_id) && f.object.parent_id
    inherited_value   = f.object.send(attr).try(:name_method)
    inherited_value ||= _("no value")
    _("Inherit parent (%s)") % inherited_value
  end

  def link_to_remove_fields(name, f, options = {})
    f.hidden_field(:_destroy) + link_to_function(icon_text('close', name, :kind => 'pficon'), "remove_fields(this)", options.merge(:title => _("Remove Parameter")))
  end

  # Creates a link to a javascript function that creates field entries for the association on the web page
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -283,7 +283,7 @@
     label = options[:label] == :none ? '' : options.delete(:label)
     label ||= ((clazz = f.object.class).respond_to?(:gettext_translation_for_attribute_name) &&
         s_(clazz.gettext_translation_for_attribute_name attr)) if f
-    label = label.present? ? label_tag(attr, "#{label}#{required_mark}".html_safe, :class => label_size + " control-label") : ''
+    label = label.present? ? label_tag(attr, "#{label}#{required_mark}", :class => label_size + " control-label") : ''
     label
   end
 
```
