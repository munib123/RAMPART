# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 663_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `663_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```python
Lines 105-145 of the vulnerable file.


    def visit_BoolOp(self, node):
        """ Boolean operator handler.
        """
        op = self.op_mapper[node.op.__class__]
        self.ops.append([])
        for value in node.values:
            self.visit(value)

        c = self.ops.pop()
        if self.ops:
            self.ops[-1].append({op: c})
        else:
            self.mongo_query[op] = c

    def visit_Call(self, node):
        """ A couple function calls are supported: bson's ObjectId() and
        datetime().
        """
        if isinstance(node.func, ast.Name):
            expr = None
            if node.func.id == 'ObjectId':
                expr = "('" + node.args[0].s + "')"
            elif node.func.id == 'datetime':
                values = []
                for arg in node.args:
                    values.append(str(arg.n))
                expr = "(" + ", ".join(values) + ")"
            if expr:
                self.current_value = eval(node.func.id + expr)

    def visit_Attribute(self, node):
        """ Attribute handler ('Contact.Id').
        """
        self.visit(node.value)
        self.current_value += "." + node.attr

    def visit_Name(self, node):
        """ Names handler.
        """
        self.current_value = node.id
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,16 +122,19 @@
         datetime().
         """
         if isinstance(node.func, ast.Name):
-            expr = None
             if node.func.id == 'ObjectId':
-                expr = "('" + node.args[0].s + "')"
+                try:
+                    self.current_value = ObjectId(node.args[0].s)
+                except:
+                    pass
             elif node.func.id == 'datetime':
                 values = []
                 for arg in node.args:
-                    values.append(str(arg.n))
-                expr = "(" + ", ".join(values) + ")"
-            if expr:
-                self.current_value = eval(node.func.id + expr)
+                    values.append(arg.n)
+                try:
+                    self.current_value = datetime(*values)
+                except:
+                    pass
 
     def visit_Attribute(self, node):
         """ Attribute handler ('Contact.Id').
```
