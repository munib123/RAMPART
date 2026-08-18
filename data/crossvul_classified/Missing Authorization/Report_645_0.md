# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 645_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `645_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 116-157 of the vulnerable file.

    errors.add(:by_group, "#{by_group} not found") if by_group && !group

    if by_project && !project
      # must be a local project or we can't ask
      errors.add(:by_project, "#{by_project} not found")
    end

    if by_package && !by_project
      errors.add(:unknown, 'by_package defined, but missing by_project')
    end
    return unless by_package && !package

    # must be a local package. maybe we should rewrite in case the
    # package comes via local project link...
    errors.add(:by_package, "#{by_project}/#{by_package} not found")
  end

  def self.new_from_xml_hash(hash)
    r = Review.new

    r.state = hash.delete('state') { raise ArgumentError, 'no state' }
    r.state = r.state.to_sym

    r.by_user = hash.delete('by_user')
    r.by_group = hash.delete('by_group')
    r.by_project = hash.delete('by_project')
    r.by_package = hash.delete('by_package')

    r.reviewer = r.creator = hash.delete('who')
    r.reason = hash.delete('comment')
    begin
      r.created_at = Time.zone.parse(hash.delete('when'))
    rescue TypeError
      # no valid time -> ignore
    end

    raise ArgumentError, "too much information #{hash.inspect}" if hash.present?
    r
  end

  def _get_attributes
    attributes = { state: state.to_s }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,8 +133,8 @@
   def self.new_from_xml_hash(hash)
     r = Review.new
 
-    r.state = hash.delete('state') { raise ArgumentError, 'no state' }
-    r.state = r.state.to_sym
+    r.state = :new
+    hash.delete('state')
 
     r.by_user = hash.delete('by_user')
     r.by_group = hash.delete('by_group')
```
