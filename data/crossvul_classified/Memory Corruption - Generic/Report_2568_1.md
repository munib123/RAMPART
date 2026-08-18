# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2568_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2568_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 708-748 of the vulnerable file.

}


int yr_object_array_set_item(
    YR_OBJECT* object,
    YR_OBJECT* item,
    int index)
{
  YR_OBJECT_ARRAY* array;

  int i;
  int count;

  assert(index >= 0);
  assert(object->type == OBJECT_TYPE_ARRAY);

  array = object_as_array(object);

  if (array->items == NULL)
  {
    count = yr_max(64, (index + 1) * 2);

    array->items = (YR_ARRAY_ITEMS*) yr_malloc(
        sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));

    if (array->items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    memset(array->items->objects, 0, count * sizeof(YR_OBJECT*));

    array->items->count = count;
  }
  else if (index >= array->items->count)
  {
    count = array->items->count * 2;
    array->items = (YR_ARRAY_ITEMS*) yr_realloc(
        array->items,
        sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));

    if (array->items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -725,7 +725,10 @@
 
   if (array->items == NULL)
   {
-    count = yr_max(64, (index + 1) * 2);
+    count = 64;
+
+    while (count <= index)
+      count *= 2;
 
     array->items = (YR_ARRAY_ITEMS*) yr_malloc(
         sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));
@@ -740,6 +743,10 @@
   else if (index >= array->items->count)
   {
     count = array->items->count * 2;
+
+    while (count <= index)
+      count *= 2;
+
     array->items = (YR_ARRAY_ITEMS*) yr_realloc(
         array->items,
         sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));
```
