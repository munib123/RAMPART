# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4032_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4032_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3142-3187 of the vulnerable file.

scan_completed:
    if (context_p->stack_top_uint8 != SCAN_STACK_SCRIPT
        && context_p->stack_top_uint8 != SCAN_STACK_SCRIPT_FUNCTION)
    {
      scanner_raise_error (context_p);
    }

    scanner_pop_literal_pool (context_p, &scanner_context);

#if ENABLED (JERRY_ES2015)
    JERRY_ASSERT (scanner_context.active_binding_list_p == NULL);
#endif /* ENABLED (JERRY_ES2015) */
    JERRY_ASSERT (scanner_context.active_literal_pool_p == NULL);

#ifndef JERRY_NDEBUG
    scanner_context.context_status_flags |= PARSER_SCANNING_SUCCESSFUL;
#endif /* !JERRY_NDEBUG */
  }
  PARSER_CATCH
  {
    /* Ignore the errors thrown by the lexer. */
    if (context_p->error != PARSER_ERR_OUT_OF_MEMORY)
    {
      context_p->error = PARSER_ERR_NO_ERROR;
    }

#if ENABLED (JERRY_ES2015)
    while (scanner_context.active_binding_list_p != NULL)
    {
      scanner_pop_binding_list (&scanner_context);
    }
#endif /* ENABLED (JERRY_ES2015) */

    /* The following code may allocate memory, so it is enclosed in a try/catch. */
    PARSER_TRY (context_p->try_buffer)
    {
#if ENABLED (JERRY_ES2015)
      if (scanner_context.status_flags & SCANNER_CONTEXT_THROW_ERR_ASYNC_FUNCTION)
      {
        JERRY_ASSERT (scanner_context.async_source_p != NULL);

        scanner_info_t *info_p;
        info_p = scanner_insert_info (context_p, scanner_context.async_source_p, sizeof (scanner_info_t));
        info_p->type = SCANNER_TYPE_ERR_ASYNC_FUNCTION;
      }
#endif /* ENABLED (JERRY_ES2015) */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3159,42 +3159,48 @@
   }
   PARSER_CATCH
   {
-    /* Ignore the errors thrown by the lexer. */
-    if (context_p->error != PARSER_ERR_OUT_OF_MEMORY)
-    {
+#if ENABLED (JERRY_ES2015)
+    while (scanner_context.active_binding_list_p != NULL)
+    {
+      scanner_pop_binding_list (&scanner_context);
+    }
+#endif /* ENABLED (JERRY_ES2015) */
+
+    if (JERRY_UNLIKELY (context_p->error != PARSER_ERR_OUT_OF_MEMORY))
+    {
+      /* Ignore the errors thrown by the lexer. */
       context_p->error = PARSER_ERR_NO_ERROR;
-    }
-
-#if ENABLED (JERRY_ES2015)
-    while (scanner_context.active_binding_list_p != NULL)
-    {
-      scanner_pop_binding_list (&scanner_context);
-    }
-#endif /* ENABLED (JERRY_ES2015) */
-
-    /* The following code may allocate memory, so it is enclosed in a try/catch. */
-    PARSER_TRY (context_p->try_buffer)
-    {
-#if ENABLED (JERRY_ES2015)
-      if (scanner_context.status_flags & SCANNER_CONTEXT_THROW_ERR_ASYNC_FUNCTION)
-      {
-        JERRY_ASSERT (scanner_context.async_source_p != NULL);
-
-        scanner_info_t *info_p;
-        info_p = scanner_insert_info (context_p, scanner_context.async_source_p, sizeof (scanner_info_t));
-        info_p->type = SCANNER_TYPE_ERR_ASYNC_FUNCTION;
-      }
-#endif /* ENABLED (JERRY_ES2015) */
-
-      while (scanner_context.active_literal_pool_p != NULL)
-      {
-        scanner_pop_literal_pool (context_p, &scanner_context);
-      }
-    }
-    PARSER_CATCH
-    {
-      JERRY_ASSERT (context_p->error == PARSER_ERR_NO_ERROR);
-
+
+      /* The following code may allocate memory, so it is enclosed in a try/catch. */
+      PARSER_TRY (context_p->try_buffer)
+      {
+  #if ENABLED (JERRY_ES2015)
+        if (scanner_context.status_flags & SCANNER_CONTEXT_THROW_ERR_ASYNC_FUNCTION)
+        {
+          JERRY_ASSERT (scanner_context.async_source_p != NULL);
+
+          scanner_info_t *info_p;
+          info_p = scanner_insert_info (context_p, scanner_context.async_source_p, sizeof (scanner_info_t));
+          info_p->type = SCANNER_TYPE_ERR_ASYNC_FUNCTION;
+        }
+  #endif /* ENABLED (JERRY_ES2015) */
+
+        while (scanner_context.active_literal_pool_p != NULL)
+        {
+          scanner_pop_literal_pool (context_p, &scanner_context);
+        }
+      }
+      PARSER_CATCH
+      {
+        JERRY_ASSERT (context_p->error == PARSER_ERR_OUT_OF_MEMORY);
+      }
+      PARSER_TRY_END
+    }
+
+    JERRY_ASSERT (context_p->error == PARSER_ERR_NO_ERROR || context_p->error == PARSER_ERR_OUT_OF_MEMORY);
+
+    if (context_p->error == PARSER_ERR_OUT_OF_MEMORY)
+    {
       while (scanner_context.active_literal_pool_p != NULL)
       {
         scanner_literal_pool_t *literal_pool_p = scanner_context.active_literal_pool_p;
@@ -3204,12 +3210,10 @@
         parser_list_free (&literal_pool_p->literal_pool);
         scanner_free (literal_pool_p, sizeof (scanner_literal_pool_t));
       }
-    }
-    PARSER_TRY_END
-
-#if ENABLED (JERRY_ES2015)
-    context_p->status_flags &= (uint32_t) ~PARSER_IS_GENERATOR_FUNCTION;
-#endif /* ENABLED (JERRY_ES2015) */
+
+      parser_stack_free (context_p);
+      return;
+    }
   }
   PARSER_TRY_END
 
```
