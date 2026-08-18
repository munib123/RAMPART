# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4461_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4461_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 24-64 of the vulnerable file.

  end

  def full?
    access?('full')
  end

  def ensure_group!
    return if record.group_id

    raise Exceptions::UnprocessableEntity, "Group can't be blank"
  end

  def follow_up?
    return true if user.permissions?('ticket.agent') # agents can always reopen tickets, regardless of group configuration
    return true if record.group.follow_up_possible != 'new_ticket' # check if the setting for follow_up_possible is disabled
    return true if record.state.name != 'closed' # check if the ticket state is already closed

    raise Exceptions::UnprocessableEntity, 'Cannot follow-up on a closed ticket. Please create a new ticket.'
  end

  private

  def access?(access)
    return true if agent_access?(access)

    customer_access?
  end

  def agent_access?(access)
    return false if !user.permissions?('ticket.agent')
    return true if owner?

    user.group_access?(record.group.id, access)
  end

  def owner?
    record.owner_id == user.id
  end

  def customer_access?
    return false if !user.permissions?('ticket.customer')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,10 @@
     raise Exceptions::UnprocessableEntity, 'Cannot follow-up on a closed ticket. Please create a new ticket.'
   end
 
+  def agent_read_access?
+    agent_access?('read')
+  end
+
   private
 
   def access?(access)
```
