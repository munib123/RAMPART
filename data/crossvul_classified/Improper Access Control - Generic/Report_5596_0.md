# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 5596_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5596_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 23-63 of the vulnerable file.

    @@typecasts = obj
  end

  def self.available_typecasts
    @@available_typecasts
  end

  def self.available_typecasts=(obj)
    @@available_typecasts = obj
  end

  self.typecasts = {}
  self.typecasts["integer"]       = lambda{|v| v.nil? ? nil : v.to_i}
  self.typecasts["boolean"]       = lambda{|v| v.nil? ? nil : (v.strip != "false")}
  self.typecasts["datetime"]      = lambda{|v| v.nil? ? nil : Time.parse(v).utc}
  self.typecasts["date"]          = lambda{|v| v.nil? ? nil : Date.parse(v)}
  self.typecasts["dateTime"]      = lambda{|v| v.nil? ? nil : Time.parse(v).utc}
  self.typecasts["decimal"]       = lambda{|v| v.nil? ? nil : BigDecimal(v.to_s)}
  self.typecasts["double"]        = lambda{|v| v.nil? ? nil : v.to_f}
  self.typecasts["float"]         = lambda{|v| v.nil? ? nil : v.to_f}
  self.typecasts["symbol"]        = lambda{|v| v.nil? ? nil : v.to_sym}
  self.typecasts["string"]        = lambda{|v| v.to_s}
  self.typecasts["yaml"]          = lambda{|v| v.nil? ? nil : YAML.load(v)}
  self.typecasts["base64Binary"]  = lambda{|v| v.unpack('m').first }

  self.available_typecasts = self.typecasts.keys

  def initialize(name, normalized_attributes = {})

    # unnormalize attribute values
    attributes = Hash[* normalized_attributes.map { |key, value|
      [ key, unnormalize_xml_entities(value) ]
    }.flatten]

    @name         = name.tr("-", "_")
    # leave the type alone if we don't know what it is
    @type         = self.class.available_typecasts.include?(attributes["type"]) ? attributes.delete("type") : attributes["type"]

    @nil_element  = attributes.delete("nil") == "true"
    @attributes   = undasherize_keys(attributes)
    @children     = []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,9 +40,7 @@
   self.typecasts["decimal"]       = lambda{|v| v.nil? ? nil : BigDecimal(v.to_s)}
   self.typecasts["double"]        = lambda{|v| v.nil? ? nil : v.to_f}
   self.typecasts["float"]         = lambda{|v| v.nil? ? nil : v.to_f}
-  self.typecasts["symbol"]        = lambda{|v| v.nil? ? nil : v.to_sym}
   self.typecasts["string"]        = lambda{|v| v.to_s}
-  self.typecasts["yaml"]          = lambda{|v| v.nil? ? nil : YAML.load(v)}
   self.typecasts["base64Binary"]  = lambda{|v| v.unpack('m').first }
 
   self.available_typecasts = self.typecasts.keys
```
