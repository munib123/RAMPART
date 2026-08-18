# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5838_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5838_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 130-170 of the vulnerable file.


  # Override global I18n.locale if the user has individual local preference.
  #----------------------------------------------------------------------------
  def set_individual_locale
    I18n.locale = self.preference[:locale] if self.preference[:locale]
  end

  # Generate the value of single access token if it hasn't been set already.
  #----------------------------------------------------------------------------
  def set_single_access_token
    self.single_access_token ||= update_attribute(:single_access_token, Authlogic::Random.friendly_token)
  end

  # Massage value when using Chosen select box which gives values like ["", "1,2,3"]
  #----------------------------------------------------------------------------
  def group_ids=(value)
    value = value.join.split(',').map(&:to_i) if value.map{|v| v.to_s.include?(',')}.any?
    super(value)
  end

  private

  # Suspend newly created user if signup requires an approval.
  #----------------------------------------------------------------------------
  def check_if_needs_approval
    self.suspended_at = Time.now if Setting.user_signup == :needs_approval && !self.admin
  end

  # Prevent current user from deleting herself.
  #----------------------------------------------------------------------------
  def check_if_current_user
    User.current_user.nil? || User.current_user != self
  end

  # Prevent deleting a user unless she has no artifacts left.
  #----------------------------------------------------------------------------
  def check_if_has_related_assets
    artifacts = %w(Account Campaign Lead Contact Opportunity Comment Task).inject(0) do |sum, asset|
      klass = asset.constantize
      sum += klass.assigned_to(self).count if asset != "Comment"
      sum += klass.created_by(self).count
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,6 +147,14 @@
     super(value)
   end
 
+  def to_json(options = nil)
+    [name].to_json
+  end
+
+  def to_xml(options = nil)
+    [name].to_xml
+  end
+
   private
 
   # Suspend newly created user if signup requires an approval.
```
