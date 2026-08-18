# CrossVul Fix Pair: Out-of-bounds Read in php
**Pair ID:** 1281_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1281_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```php
Lines 186-210 of the vulnerable file.

   Token value for ``"@"``.

.. data:: ATEQUAL

   Token value for ``"@="``.

.. data:: RARROW

   Token value for ``"->"``.

.. data:: ELLIPSIS

   Token value for ``"..."``.

.. data:: COLONEQUAL

   Token value for ``":="``.

.. data:: OP

.. data:: ERRORTOKEN

.. data:: N_TOKENS

.. data:: NT_OFFSET
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,6 +203,10 @@
 
 .. data:: OP
 
+.. data:: TYPE_IGNORE
+
+.. data:: TYPE_COMMENT
+
 .. data:: ERRORTOKEN
 
 .. data:: N_TOKENS
```
