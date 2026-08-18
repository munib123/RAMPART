# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 4605_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4605_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 1-22 of the vulnerable file.

from django.contrib.postgres.fields import ArrayField, JSONField
from django.db.models.aggregates import Aggregate

from .mixins import OrderableAggMixin

__all__ = [
    'ArrayAgg', 'BitAnd', 'BitOr', 'BoolAnd', 'BoolOr', 'JSONBAgg', 'StringAgg',
]


class ArrayAgg(OrderableAggMixin, Aggregate):
    function = 'ARRAY_AGG'
    template = '%(function)s(%(distinct)s%(expressions)s %(ordering)s)'
    allow_distinct = True

    @property
    def output_field(self):
        return ArrayField(self.source_expressions[0].output_field)

    def convert_value(self, value, expression, connection):
        if not value:
            return []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 from django.contrib.postgres.fields import ArrayField, JSONField
+from django.db.models import Value
 from django.db.models.aggregates import Aggregate
 
 from .mixins import OrderableAggMixin
@@ -51,11 +52,12 @@
 
 class StringAgg(OrderableAggMixin, Aggregate):
     function = 'STRING_AGG'
-    template = "%(function)s(%(distinct)s%(expressions)s, '%(delimiter)s'%(ordering)s)"
+    template = '%(function)s(%(distinct)s%(expressions)s %(ordering)s)'
     allow_distinct = True
 
     def __init__(self, expression, delimiter, **extra):
-        super().__init__(expression, delimiter=delimiter, **extra)
+        delimiter_expr = Value(str(delimiter))
+        super().__init__(expression, delimiter_expr, **extra)
 
     def convert_value(self, value, expression, connection):
         if not value:
```
