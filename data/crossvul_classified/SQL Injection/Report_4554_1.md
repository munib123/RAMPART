# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 4554_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4554_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 32-72 of the vulnerable file.

    context "when `order` argument is valid" do
      it "orders by the column" do
        order = Administrate::Order.new(:name, :asc)
        relation = relation_with_column(:name)
        allow(relation).to receive(:reorder).and_return(relation)

        ordered = order.apply(relation)

        expect(relation).to have_received(:reorder).with("table_name.name asc")
        expect(ordered).to eq(relation)
      end

      it "honors the `direction` argument" do
        order = Administrate::Order.new(:name, :desc)
        relation = relation_with_column(:name)
        allow(relation).to receive(:reorder).and_return(relation)

        ordered = order.apply(relation)

        expect(relation).to have_received(:reorder).with("table_name.name desc")
        expect(ordered).to eq(relation)
      end
    end

    context "when relation has_many association" do
      it "orders the column by count" do
        order = Administrate::Order.new(:name)
        relation = relation_with_association(:has_many)
        allow(relation).to receive(:reorder).and_return(relation)
        allow(relation).to receive(:left_joins).and_return(relation)
        allow(relation).to receive(:group).and_return(relation)

        ordered = order.apply(relation)

        expect(relation).to have_received(:left_joins).with(:name)
        expect(relation).to have_received(:group).with(:id)
        expect(relation).to have_received(:reorder).with("COUNT(name.id) asc")
        expect(ordered).to eq(relation)
      end
    end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,6 +49,17 @@
         ordered = order.apply(relation)
 
         expect(relation).to have_received(:reorder).with("table_name.name desc")
+        expect(ordered).to eq(relation)
+      end
+
+      it "sanitizes arbitary direction parameters" do
+        order = Administrate::Order.new(:name, :foo)
+        relation = relation_with_column(:name)
+        allow(relation).to receive(:reorder).and_return(relation)
+
+        ordered = order.apply(relation)
+
+        expect(relation).to have_received(:reorder).with("table_name.name asc")
         expect(ordered).to eq(relation)
       end
     end
```
