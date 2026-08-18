# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3348_5
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3348_5`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 556-596 of the vulnerable file.

  YR_OBJECT* copy;
  YR_OBJECT* o;

  YR_STRUCTURE_MEMBER* structure_member;
  YR_OBJECT_FUNCTION* func;
  YR_OBJECT_FUNCTION* func_copy;

  int i;

  *object_copy = NULL;

  FAIL_ON_ERROR(yr_object_create(
      object->type,
      object->identifier,
      NULL,
      &copy));

  switch(object->type)
  {
    case OBJECT_TYPE_INTEGER:
      ((YR_OBJECT_INTEGER*) copy)->value = UNDEFINED;
      break;

    case OBJECT_TYPE_STRING:
      ((YR_OBJECT_STRING*) copy)->value = NULL;
      break;

    case OBJECT_TYPE_FUNCTION:

      func = (YR_OBJECT_FUNCTION*) object;
      func_copy = (YR_OBJECT_FUNCTION*) copy;

      FAIL_ON_ERROR_WITH_CLEANUP(
        yr_object_copy(func->return_obj, &func_copy->return_obj),
        yr_object_destroy(copy));

      for (i = 0; i < MAX_OVERLOADED_FUNCTIONS; i++)
        func_copy->prototypes[i] = func->prototypes[i];

      break;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -573,11 +573,23 @@
   switch(object->type)
   {
     case OBJECT_TYPE_INTEGER:
-      ((YR_OBJECT_INTEGER*) copy)->value = UNDEFINED;
+      ((YR_OBJECT_INTEGER*) copy)->value = ((YR_OBJECT_INTEGER*) object)->value;
       break;
 
     case OBJECT_TYPE_STRING:
-      ((YR_OBJECT_STRING*) copy)->value = NULL;
+      if (((YR_OBJECT_STRING*) object)->value != NULL)
+      {
+        ((YR_OBJECT_STRING*) copy)->value = sized_string_dup(
+            ((YR_OBJECT_STRING*) object)->value);
+      }
+      else
+      {
+        ((YR_OBJECT_STRING*) copy)->value = NULL;
+      }
+      break;
+
+    case OBJECT_TYPE_FLOAT:
+      ((YR_OBJECT_DOUBLE*) copy)->value = ((YR_OBJECT_DOUBLE*) object)->value;
       break;
 
     case OBJECT_TYPE_FUNCTION:
```
