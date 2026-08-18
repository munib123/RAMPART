# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2767_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2767_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 291-331 of the vulnerable file.

                                    "source sequence is illegal/malformed utf-8");
                        }
                        end += clen;
                    }
                    continue;
                    break;
            }
        }
        fbuffer_append(buffer, ptr + start, end - start);
        fbuffer_append(buffer, escape, escape_len);
        start = ++end;
        escape = NULL;
    }
    fbuffer_append(buffer, ptr + start, end - start);
}

static char *fstrndup(const char *ptr, unsigned long len) {
  char *result;
  if (len <= 0) return NULL;
  result = ALLOC_N(char, len);
  memccpy(result, ptr, 0, len);
  return result;
}

/*
 * Document-module: JSON::Ext::Generator
 *
 * This is the JSON generator implemented as a C extension. It can be
 * configured to be used by setting
 *
 *  JSON.generator = JSON::Ext::Generator
 *
 * with the method generator= in JSON.
 *
 */

/*
 * call-seq: to_json(state = nil)
 *
 * Returns a JSON string containing a JSON object, that is generated from
 * this Hash instance.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -308,7 +308,7 @@
   char *result;
   if (len <= 0) return NULL;
   result = ALLOC_N(char, len);
-  memccpy(result, ptr, 0, len);
+  memcpy(result, ptr, len);
   return result;
 }
 
@@ -1062,7 +1062,7 @@
         }
     } else {
         if (state->indent) ruby_xfree(state->indent);
-        state->indent = strdup(RSTRING_PTR(indent));
+        state->indent = fstrndup(RSTRING_PTR(indent), len);
         state->indent_len = len;
     }
     return Qnil;
@@ -1100,7 +1100,7 @@
         }
     } else {
         if (state->space) ruby_xfree(state->space);
-        state->space = strdup(RSTRING_PTR(space));
+        state->space = fstrndup(RSTRING_PTR(space), len);
         state->space_len = len;
     }
     return Qnil;
@@ -1136,7 +1136,7 @@
         }
     } else {
         if (state->space_before) ruby_xfree(state->space_before);
-        state->space_before = strdup(RSTRING_PTR(space_before));
+        state->space_before = fstrndup(RSTRING_PTR(space_before), len);
         state->space_before_len = len;
     }
     return Qnil;
@@ -1173,7 +1173,7 @@
         }
     } else {
         if (state->object_nl) ruby_xfree(state->object_nl);
-        state->object_nl = strdup(RSTRING_PTR(object_nl));
+        state->object_nl = fstrndup(RSTRING_PTR(object_nl), len);
         state->object_nl_len = len;
     }
     return Qnil;
@@ -1208,7 +1208,7 @@
         }
     } else {
         if (state->array_nl) ruby_xfree(state->array_nl);
-        state->array_nl = strdup(RSTRING_PTR(array_nl));
+        state->array_nl = fstrndup(RSTRING_PTR(array_nl), len);
         state->array_nl_len = len;
     }
     return Qnil;
```
