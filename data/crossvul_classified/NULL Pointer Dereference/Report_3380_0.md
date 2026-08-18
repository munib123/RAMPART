# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3380_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3380_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1180-1220 of the vulnerable file.

    if (literal_p->type == literal_type
        && literal_p->prop.length == length
        && memcmp (literal_p->u.char_p, char_p, length) == 0)
    {
      context_p->lit_object.literal_p = literal_p;
      context_p->lit_object.index = (uint16_t) literal_index;
      literal_p->status_flags = (uint8_t) (literal_p->status_flags & ~LEXER_FLAG_UNUSED_IDENT);
      return;
    }

    literal_index++;
  }

  JERRY_ASSERT (literal_index == context_p->literal_count);

  if (literal_index >= PARSER_MAXIMUM_NUMBER_OF_LITERALS)
  {
    parser_raise_error (context_p, PARSER_ERR_LITERAL_LIMIT_REACHED);
  }

  literal_p = (lexer_literal_t *) parser_list_append (context_p, &context_p->literal_pool);
  literal_p->prop.length = (uint16_t) length;
  literal_p->type = literal_type;
  literal_p->status_flags = has_escape ? 0 : LEXER_FLAG_SOURCE_PTR;

  if (has_escape)
  {
    literal_p->u.char_p = (uint8_t *) jmem_heap_alloc_block (length);
    memcpy ((uint8_t *) literal_p->u.char_p, char_p, length);
  }
  else
  {
    literal_p->u.char_p = char_p;
  }

  context_p->lit_object.literal_p = literal_p;
  context_p->lit_object.index = (uint16_t) literal_index;
  context_p->literal_count++;
} /* lexer_process_char_literal */

/* Maximum buffer size for identifiers which contains escape sequences. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1195,6 +1195,11 @@
   if (literal_index >= PARSER_MAXIMUM_NUMBER_OF_LITERALS)
   {
     parser_raise_error (context_p, PARSER_ERR_LITERAL_LIMIT_REACHED);
+  }
+
+  if (length == 0)
+  {
+    has_escape = false;
   }
 
   literal_p = (lexer_literal_t *) parser_list_append (context_p, &context_p->literal_pool);
```
