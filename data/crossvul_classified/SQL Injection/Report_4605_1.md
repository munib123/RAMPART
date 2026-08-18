# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 4605_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4605_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 1-26 of the vulnerable file.

from django.db.models.expressions import F, OrderBy


class OrderableAggMixin:

    def __init__(self, expression, ordering=(), **extra):
        if not isinstance(ordering, (list, tuple)):
            ordering = [ordering]
        ordering = ordering or []
        # Transform minus sign prefixed strings into an OrderBy() expression.
        ordering = (
            (OrderBy(F(o[1:]), descending=True) if isinstance(o, str) and o[0] == '-' else o)
            for o in ordering
        )
        super().__init__(expression, **extra)
        self.ordering = self._parse_expressions(*ordering)

    def resolve_expression(self, *args, **kwargs):
        self.ordering = [expr.resolve_expression(*args, **kwargs) for expr in self.ordering]
        return super().resolve_expression(*args, **kwargs)

    def as_sql(self, compiler, connection):
        if self.ordering:
            ordering_params = []
            ordering_expr_sql = []
            for expr in self.ordering:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 
 class OrderableAggMixin:
 
-    def __init__(self, expression, ordering=(), **extra):
+    def __init__(self, *expressions, ordering=(), **extra):
         if not isinstance(ordering, (list, tuple)):
             ordering = [ordering]
         ordering = ordering or []
@@ -12,7 +12,7 @@
             (OrderBy(F(o[1:]), descending=True) if isinstance(o, str) and o[0] == '-' else o)
             for o in ordering
         )
-        super().__init__(expression, **extra)
+        super().__init__(*expressions, **extra)
         self.ordering = self._parse_expressions(*ordering)
 
     def resolve_expression(self, *args, **kwargs):
```
