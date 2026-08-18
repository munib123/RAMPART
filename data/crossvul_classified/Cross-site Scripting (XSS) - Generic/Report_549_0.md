# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 549_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `549_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-31 of the vulnerable file.

# frozen_string_literal: true

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
module TagsHelper
  # Generate tag links for use on asset index pages.
  #----------------------------------------------------------------------------
  def tags_for_index(model)
    model.tags.inject("".html_safe) do |out, tag|
      query = controller.send(:current_query) || ""
      hashtag = "##{tag}"
      if query.empty?
        query = hashtag
      elsif !query.include?(hashtag)
        query += " #{hashtag}"
      end
      out << link_to_function(tag, "crm.search_tagged('#{query}', '#{model.class.to_s.tableize}')", title: tag)
    end
  end

  def tags_for_dashboard(model)
    content_tag(:ul) do
      model.tags.each do |tag|
        concat(content_tag(:li, tag.name))
      end
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
       elsif !query.include?(hashtag)
         query += " #{hashtag}"
       end
-      out << link_to_function(tag, "crm.search_tagged('#{query}', '#{model.class.to_s.tableize}')", title: tag)
+      out << link_to_function(tag, "crm.search_tagged('#{escape_javascript(query)}', '#{model.class.to_s.tableize}')", title: tag)
     end
   end
 
```
