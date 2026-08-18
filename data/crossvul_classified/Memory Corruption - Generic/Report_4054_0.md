# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4054_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4054_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 47-88 of the vulnerable file.

static inline ecma_collection_t *
ecma_op_create_internal_buffer (void)
{
  ecma_collection_t *collection_p = ecma_new_collection ();
  ecma_collection_push_back (collection_p, (ecma_value_t) 0);

  return collection_p;
} /* ecma_op_create_internal_buffer */

/**
 * Append values to the internal buffer.
 */
static void
ecma_op_internal_buffer_append (ecma_collection_t *container_p, /**< internal container pointer */
                                ecma_value_t key_arg, /**< key argument */
                                ecma_value_t value_arg, /**< value argument */
                                lit_magic_string_id_t lit_id) /**< class id */
{
  JERRY_ASSERT (container_p != NULL);

  ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (key_arg));

  if (lit_id == LIT_MAGIC_STRING_WEAKMAP_UL || lit_id == LIT_MAGIC_STRING_MAP_UL)
  {
    ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (value_arg));
  }

  ECMA_CONTAINER_SET_SIZE (container_p, ECMA_CONTAINER_GET_SIZE (container_p) + 1);
} /* ecma_op_internal_buffer_append */

/**
 * Update the value of a given entry.
 */
static inline void
ecma_op_internal_buffer_update (ecma_value_t *entry_p, /**< entry pointer */
                                ecma_value_t value_arg, /**< value argument */
                                lit_magic_string_id_t lit_id) /**< class id */
{
  JERRY_ASSERT (entry_p != NULL);

  if (lit_id == LIT_MAGIC_STRING_WEAKMAP_UL || lit_id == LIT_MAGIC_STRING_MAP_UL)
  {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,11 +64,14 @@
 {
   JERRY_ASSERT (container_p != NULL);
 
-  ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (key_arg));
-
   if (lit_id == LIT_MAGIC_STRING_WEAKMAP_UL || lit_id == LIT_MAGIC_STRING_MAP_UL)
   {
-    ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (value_arg));
+    ecma_value_t values[] = { ecma_copy_value_if_not_object (key_arg), ecma_copy_value_if_not_object (value_arg) };
+    ecma_collection_append (container_p, values, 2);
+  }
+  else
+  {
+    ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (key_arg));
   }
 
   ECMA_CONTAINER_SET_SIZE (container_p, ECMA_CONTAINER_GET_SIZE (container_p) + 1);
```
