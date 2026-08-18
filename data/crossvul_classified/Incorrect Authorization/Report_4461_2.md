# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4461_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4461_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 1-15 of the vulnerable file.

FactoryBot.define do
  factory :role do
    sequence(:name) { |n| "TestRole#{n}" }
    created_by_id   { 1 }
    updated_by_id   { 1 }

    factory :agent_role do
      permissions { Permission.where(name: 'ticket.agent') }
    end

    trait :admin do
      permissions { Permission.where(name: 'admin') }
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,10 @@
       permissions { Permission.where(name: 'ticket.agent') }
     end
 
+    trait :customer do
+      permissions { Permission.where(name: 'ticket.customer') }
+    end
+
     trait :admin do
       permissions { Permission.where(name: 'admin') }
     end
```
