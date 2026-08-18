# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3348_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3348_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 67-107 of the vulnerable file.

    YR_OBJECT* parent,
    YR_OBJECT** object);


int yr_object_function_create(
    const char* identifier,
    const char* arguments_fmt,
    const char* return_fmt,
    YR_MODULE_FUNC func,
    YR_OBJECT* parent,
    YR_OBJECT** function);


int yr_object_from_external_variable(
    YR_EXTERNAL_VARIABLE* external,
    YR_OBJECT** object);


void yr_object_destroy(
    YR_OBJECT* object);


YR_OBJECT* yr_object_lookup_field(
    YR_OBJECT* object,
    const char* field_name);


YR_OBJECT* yr_object_lookup(
    YR_OBJECT* root,
    int flags,
    const char* pattern,
    ...);


int yr_object_has_undefined_value(
    YR_OBJECT* object,
    const char* field,
    ...);

int64_t yr_object_get_integer(
    YR_OBJECT* object,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,6 +84,11 @@
 
 void yr_object_destroy(
     YR_OBJECT* object);
+
+
+int yr_object_copy(
+    YR_OBJECT* object,
+    YR_OBJECT** object_copy);
 
 
 YR_OBJECT* yr_object_lookup_field(
```
