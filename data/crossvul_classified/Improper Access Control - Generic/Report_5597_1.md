# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5597_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5597_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 1-24 of the vulnerable file.

class ParseAtom
  include HTTParty

  # Support Atom along with the default parsers: xml, json, yaml, etc.
  class Parser::Atom < HTTParty::Parser
    SupportedFormats.merge!({"application/atom+xml" => :atom})

    protected

    # perform atom parsing on body
    def atom
      body.to_atom
    end
  end

  parser Parser::Atom
end


class OnlyParseAtom
  include HTTParty

  # Only support Atom
  class Parser::OnlyAtom < HTTParty::Parser
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 class ParseAtom
   include HTTParty
 
-  # Support Atom along with the default parsers: xml, json, yaml, etc.
+  # Support Atom along with the default parsers: xml, json, etc.
   class Parser::Atom < HTTParty::Parser
     SupportedFormats.merge!({"application/atom+xml" => :atom})
 
```
