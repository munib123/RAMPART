# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 4055_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4055_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 1-5 of the vulnerable file.

class Controllers::TicketsControllerPolicy < Controllers::ApplicationControllerPolicy
  permit! %i[import_example import_start], to: 'admin'
  permit! :selector, to: 'admin.*'
  permit! :create, to: ['ticket.agent', 'ticket.customer']
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 class Controllers::TicketsControllerPolicy < Controllers::ApplicationControllerPolicy
   permit! %i[import_example import_start], to: 'admin'
   permit! :selector, to: 'admin.*'
+  permit! %i[ticket_customer ticket_history ticket_related ticket_recent ticket_merge ticket_split], to: 'ticket.agent'
   permit! :create, to: ['ticket.agent', 'ticket.customer']
 end
```
