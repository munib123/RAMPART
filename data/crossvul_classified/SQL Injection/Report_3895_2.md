# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 3895_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3895_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

from pypika import Parameter, functions
from pypika.enums import SqlTypes
from pypika.terms import Criterion

from tortoise import Model
from tortoise.backends.base.executor import BaseExecutor
from tortoise.fields import BigIntField, Field, IntField, SmallIntField
from tortoise.filters import (
    contains,
    ends_with,
    insensitive_contains,
    insensitive_ends_with,
    insensitive_exact,
    insensitive_starts_with,
    starts_with,
)


def mysql_contains(field: Field, value: str) -> Criterion:
    return functions.Cast(field, SqlTypes.CHAR).like(f"%{value}%")


def mysql_starts_with(field: Field, value: str) -> Criterion:
    return functions.Cast(field, SqlTypes.CHAR).like(f"{value}%")


def mysql_ends_with(field: Field, value: str) -> Criterion:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,10 +4,14 @@
 
 from tortoise import Model
 from tortoise.backends.base.executor import BaseExecutor
-from tortoise.fields import BigIntField, Field, IntField, SmallIntField
+from tortoise.fields import BigIntField, IntField, SmallIntField
 from tortoise.filters import (
+    Like,
+    Term,
+    ValueWrapper,
     contains,
     ends_with,
+    format_quotes,
     insensitive_contains,
     insensitive_ends_with,
     insensitive_exact,
@@ -16,32 +20,65 @@
 )
 
 
-def mysql_contains(field: Field, value: str) -> Criterion:
-    return functions.Cast(field, SqlTypes.CHAR).like(f"%{value}%")
+class StrWrapper(ValueWrapper):  # type: ignore
+    """
+    Naive str wrapper that doesn't use the monkey-patched pypika ValueWraper for MySQL
+    """
+
+    def get_value_sql(self, **kwargs):
+        quote_char = kwargs.get("secondary_quote_char") or ""
+        value = self.value.replace(quote_char, quote_char * 2)
+        return format_quotes(value, quote_char)
 
 
-def mysql_starts_with(field: Field, value: str) -> Criterion:
-    return functions.Cast(field, SqlTypes.CHAR).like(f"{value}%")
+def escape_like(val: str) -> str:
+    return val.replace("\\", "\\\\\\\\").replace("%", "\\%").replace("_", "\\_")
 
 
-def mysql_ends_with(field: Field, value: str) -> Criterion:
-    return functions.Cast(field, SqlTypes.CHAR).like(f"%{value}")
+def mysql_contains(field: Term, value: str) -> Criterion:
+    return Like(
+        functions.Cast(field, SqlTypes.CHAR), StrWrapper(f"%{escape_like(value)}%"), escape=""
+    )
 
 
-def mysql_insensitive_exact(field: Field, value: str) -> Criterion:
-    return functions.Upper(functions.Cast(field, SqlTypes.CHAR)).eq(functions.Upper(f"{value}"))
+def mysql_starts_with(field: Term, value: str) -> Criterion:
+    return Like(
+        functions.Cast(field, SqlTypes.CHAR), StrWrapper(f"{escape_like(value)}%"), escape=""
+    )
 
 
-def mysql_insensitive_contains(field: Field, value: str) -> Criterion:
-    return functions.Upper(functions.Cast(field, SqlTypes.CHAR)).like(functions.Upper(f"%{value}%"))
+def mysql_ends_with(field: Term, value: str) -> Criterion:
+    return Like(
+        functions.Cast(field, SqlTypes.CHAR), StrWrapper(f"%{escape_like(value)}"), escape=""
+    )
 
 
-def mysql_insensitive_starts_with(field: Field, value: str) -> Criterion:
-    return functions.Upper(functions.Cast(field, SqlTypes.CHAR)).like(functions.Upper(f"{value}%"))
+def mysql_insensitive_exact(field: Term, value: str) -> Criterion:
+    return functions.Upper(functions.Cast(field, SqlTypes.CHAR)).eq(functions.Upper(str(value)))
 
 
-def mysql_insensitive_ends_with(field: Field, value: str) -> Criterion:
-    return functions.Upper(functions.Cast(field, SqlTypes.CHAR)).like(functions.Upper(f"%{value}"))
+def mysql_insensitive_contains(field: Term, value: str) -> Criterion:
+    return Like(
+        functions.Upper(functions.Cast(field, SqlTypes.CHAR)),
+        functions.Upper(StrWrapper(f"%{escape_like(value)}%")),
+        escape="",
+    )
+
+
+def mysql_insensitive_starts_with(field: Term, value: str) -> Criterion:
+    return Like(
+        functions.Upper(functions.Cast(field, SqlTypes.CHAR)),
+        functions.Upper(StrWrapper(f"{escape_like(value)}%")),
+        escape="",
+    )
+
+
+def mysql_insensitive_ends_with(field: Term, value: str) -> Criterion:
+    return Like(
+        functions.Upper(functions.Cast(field, SqlTypes.CHAR)),
+        functions.Upper(StrWrapper(f"%{escape_like(value)}")),
+        escape="",
+    )
 
 
 class MySQLExecutor(BaseExecutor):
```
