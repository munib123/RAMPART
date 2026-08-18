# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4461_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4461_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 38-63 of the vulnerable file.

    end

    true
  end

  private

  def deletable_timeframe_setting
    Setting.get('ui_ticket_zoom_article_delete_timeframe')
  end

  def deletable_timeframe?
    deletable_timeframe_setting&.positive?
  end

  def deletable_timeframe
    deletable_timeframe_setting.seconds
  end

  def access?(query)
    return false if record.internal == true && !user.permissions?('ticket.agent')

    ticket = Ticket.lookup(id: record.ticket_id)
    Pundit.authorize(user, ticket, query)
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,9 +55,9 @@
   end
 
   def access?(query)
-    return false if record.internal == true && !user.permissions?('ticket.agent')
+    ticket = Ticket.lookup(id: record.ticket_id)
+    return false if record.internal == true && !TicketPolicy.new(user, ticket).agent_read_access?
 
-    ticket = Ticket.lookup(id: record.ticket_id)
     Pundit.authorize(user, ticket, query)
   end
 end
```
