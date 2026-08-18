# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4461_3
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4461_3`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 12-52 of the vulnerable file.

  end

  context 'when article internal' do
    let(:record) do
      ticket = create(:ticket, group: group, customer: ticket_customer)
      create(:ticket_article, ticket: ticket, internal: true)
    end

    context 'when agent' do
      let(:user) { create(:agent, groups: [group]) }

      it { is_expected.to permit_actions(%i[show]) }
    end

    context 'when agent and customer' do
      let(:user) { create(:agent_and_customer, groups: [group]) }

      it { is_expected.to permit_actions(%i[show]) }
    end

    context 'when customer' do
      let(:user) { ticket_customer }

      it { is_expected.not_to permit_actions(%i[show]) }
    end
  end

  context 'when agent' do
    let(:user) { create(:agent, groups: [group]) }

    it { is_expected.to permit_actions(%i[show]) }
  end

  context 'when agent and customer' do
    let(:user) { create(:agent_and_customer, groups: [group]) }

    it { is_expected.to permit_actions(%i[show]) }
  end

  context 'when customer' do
    let(:user) { ticket_customer }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,15 @@
       it { is_expected.to permit_actions(%i[show]) }
     end
 
+    context 'when agent and customer but no agent group access' do
+      let(:user) do
+        customer_role = create(:role, :customer)
+        create(:agent_and_customer, roles: [customer_role])
+      end
+
+      it { is_expected.not_to permit_actions(%i[show]) }
+    end
+
     context 'when customer' do
       let(:user) { ticket_customer }
 
```
