# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 542_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `542_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 187-227 of the vulnerable file.

      email: 'change@me-' + SecureRandom.hex(5) + '.anonymous'
    )

    # anonymize cached attributes (topics)
    self.topics.update_all(user_name: 'Anonymized User')

    # rebuild index
  end

  # Unassign from all tickets
  def unassign_all
    Topic.where(assigned_user_id: self.id).update_all(assigned_user_id: nil)
  end

  # Can this user be deleted? Protects admins/system user from accidental delete
  def can_scrub_and_delete?
    return false if self.id == 2 || self.is_admin?
    true
  end

  def self.notifiable_on_public
    agents.where(notify_on_public: true).reorder('id asc')
  end

  def self.notifiable_on_private
    agents.where(notify_on_private: true).reorder('id asc')
  end

  def self.notifiable_on_reply
    agents.where(notify_on_reply: true).reorder('id asc')
  end

  def active_assigned_count
    Topic.where(assigned_user_id: self.id).active.count
  end

  def is_restricted?
    self.team_list.count > 0 && !self.is_admin?
  end

  def self.create_password
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,6 +204,12 @@
     true
   end
 
+  # Is this user editable by the current logged in agent?
+  def can_be_edited? current_user
+    return true if current_user.is_admin?
+    !self.is_agent?
+  end
+
   def self.notifiable_on_public
     agents.where(notify_on_public: true).reorder('id asc')
   end
```
