# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 3895_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3895_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

import operator
from functools import partial
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple

from pypika import Table
from pypika.functions import Upper
from pypika.terms import BasicCriterion, Criterion, Equality, Term, ValueWrapper

from tortoise.fields import Field
from tortoise.fields.relational import BackwardFKRelation, ManyToManyFieldInstance

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model

##############################################################################
# Encoders
# Should be type: (Any, instance: "Model", field: Field) -> type:
##############################################################################


def list_encoder(values: Iterable[Any], instance: "Model", field: Field) -> list:
    """Encodes an iterable of a given field into a database-compatible format."""
    return [field.to_db_value(element, instance) for element in values]


def related_list_encoder(values: Iterable[Any], instance: "Model", field: Field) -> list:
    return [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,13 +4,88 @@
 
 from pypika import Table
 from pypika.functions import Upper
-from pypika.terms import BasicCriterion, Criterion, Equality, Term, ValueWrapper
+from pypika.terms import (
+    BasicCriterion,
+    Criterion,
+    Enum,
+    Equality,
+    Term,
+    ValueWrapper,
+    basestring,
+    date,
+    format_quotes,
+)
 
 from tortoise.fields import Field
 from tortoise.fields.relational import BackwardFKRelation, ManyToManyFieldInstance
 
 if TYPE_CHECKING:  # pragma: nocoverage
     from tortoise.models import Model
+
+##############################################################################
+# Here we monkey-patch PyPika Valuewrapper to behave differently for MySQL
+##############################################################################
+
+
+def get_value_sql(self, **kwargs):  # pragma: nocoverage
+    quote_char = kwargs.get("secondary_quote_char") or ""
+    dialect = kwargs.get("dialect")
+    if dialect:
+        dialect = dialect.value
+
+    if isinstance(self.value, Term):
+        return self.value.get_sql(**kwargs)
+    if isinstance(self.value, Enum):
+        return self.value.value
+    if isinstance(self.value, date):
+        value = self.value.isoformat()
+        return format_quotes(value, quote_char)
+    if isinstance(self.value, basestring):
+        value = self.value.replace(quote_char, quote_char * 2)
+        if dialect == "mysql":
+            value = value.replace("\\", "\\\\")
+        return format_quotes(value, quote_char)
+    if isinstance(self.value, bool):
+        return str.lower(str(self.value))
+    if self.value is None:
+        return "null"
+    return str(self.value)
+
+
+ValueWrapper.get_value_sql = get_value_sql
+##############################################################################
+
+
+class Like(BasicCriterion):  # type: ignore
+    def __init__(self, left, right, alias=None, escape=" ESCAPE '\\'") -> None:
+        """
+        A Like that supports an ESCAPE clause
+        """
+        super().__init__(" LIKE ", left, right, alias=alias)
+        self.escape = escape
+
+    def get_sql(self, quote_char='"', with_alias=False, **kwargs):
+        sql = "{left}{comparator}{right}{escape}".format(
+            comparator=self.comparator,
+            left=self.left.get_sql(quote_char=quote_char, **kwargs),
+            right=self.right.get_sql(quote_char=quote_char, **kwargs),
+            escape=self.escape,
+        )
+        if with_alias and self.alias:  # pragma: nocoverage
+            return '{sql} "{alias}"'.format(sql=sql, alias=self.alias)
+        return sql
+
+
+def escape_val(val: Any) -> Any:
+    if isinstance(val, str):
+        print(val)
+        return val.replace("\\", "\\\\")
+    return val
+
+
+def escape_like(val: str) -> str:
+    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
+
 
 ##############################################################################
 # Encoders
@@ -79,31 +154,31 @@
 
 
 def contains(field: Term, value: str) -> Criterion:
-    return field.like(f"%{value}%")
+    return Like(field, field.wrap_constant(f"%{escape_like(value)}%"))
 
 
 def starts_with(field: Term, value: str) -> Criterion:
-    return field.like(f"{value}%")
+    return Like(field, field.wrap_constant(f"{escape_like(value)}%"))
 
 
 def ends_with(field: Term, value: str) -> Criterion:
-    return field.like(f"%{value}")
+    return Like(field, field.wrap_constant(f"%{escape_like(value)}"))
 
 
 def insensitive_exact(field: Term, value: str) -> Criterion:
-    return Upper(field).eq(Upper(f"{value}"))
+    return Upper(field).eq(Upper(str(value)))
 
 
 def insensitive_contains(field: Term, value: str) -> Criterion:
-    return Upper(field).like(Upper(f"%{value}%"))
+    return Like(Upper(field), field.wrap_constant(Upper(f"%{escape_like(value)}%")))
 
 
 def insensitive_starts_with(field: Term, value: str) -> Criterion:
-    return Upper(field).like(Upper(f"{value}%"))
+    return Like(Upper(field), field.wrap_constant(Upper(f"{escape_like(value)}%")))
 
 
 def insensitive_ends_with(field: Term, value: str) -> Criterion:
-    return Upper(field).like(Upper(f"%{value}"))
+    return Like(Upper(field), field.wrap_constant(Upper(f"%{escape_like(value)}")))
 
 
 ##############################################################################
```
