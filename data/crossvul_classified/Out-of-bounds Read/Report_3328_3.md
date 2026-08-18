# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3328_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3328_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 511-551 of the vulnerable file.

      new_match->base = callback_args->data_base;
      new_match->offset = match_offset;
      new_match->match_length = match_length;
      new_match->prev = NULL;
      new_match->next = NULL;

      FAIL_ON_ERROR(_yr_scan_add_match_to_list(
          new_match,
          &string->matches[tidx],
          STRING_IS_GREEDY_REGEXP(string)));
    }
  }

  return result;
}


typedef int (*RE_EXEC_FUNC)(
    uint8_t* code,
    uint8_t* input,
    size_t input_size,
    int flags,
    RE_MATCH_CALLBACK_FUNC callback,
    void* callback_args);


int _yr_scan_verify_re_match(
    YR_SCAN_CONTEXT* context,
    YR_AC_MATCH* ac_match,
    uint8_t* data,
    size_t data_size,
    size_t data_base,
    size_t offset)
{
  CALLBACK_ARGS callback_args;
  RE_EXEC_FUNC exec;

  int forward_matches = -1;
  int backward_matches = -1;
  int flags = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -528,7 +528,8 @@
 typedef int (*RE_EXEC_FUNC)(
     uint8_t* code,
     uint8_t* input,
-    size_t input_size,
+    size_t input_forwards_size,
+    size_t input_backwards_size,
     int flags,
     RE_MATCH_CALLBACK_FUNC callback,
     void* callback_args);
@@ -569,7 +570,8 @@
         ac_match->forward_code,
         data + offset,
         data_size - offset,
-        offset > 0 ? flags | RE_FLAGS_NOT_AT_START : flags,
+        offset,
+        flags,
         NULL,
         NULL);
   }
@@ -581,7 +583,8 @@
         ac_match->forward_code,
         data + offset,
         data_size - offset,
-        offset > 0 ? flags | RE_FLAGS_NOT_AT_START : flags,
+        offset,
+        flags,
         NULL,
         NULL);
   }
@@ -616,6 +619,7 @@
     backward_matches = exec(
         ac_match->backward_code,
         data + offset,
+        data_size - offset,
         offset,
         flags | RE_FLAGS_BACKWARDS | RE_FLAGS_EXHAUSTIVE,
         _yr_scan_match_callback,
```
