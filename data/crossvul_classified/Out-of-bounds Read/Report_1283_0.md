# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1283_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1283_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1428-1468 of the vulnerable file.

                    /* ch is NAME ':' test */
                    annotation = ast_for_expr(c, CHILD(ch, 2));
                    if (!annotation)
                        goto error;
                }
                else {
                    annotation = NULL;
                }
                ch = CHILD(ch, 0);
                argname = NEW_IDENTIFIER(ch);
                if (!argname)
                    goto error;
                if (forbidden_name(c, argname, ch, 0))
                    goto error;
                arg = arg(argname, annotation, NULL, LINENO(ch), ch->n_col_offset,
                          c->c_arena);
                if (!arg)
                    goto error;
                asdl_seq_SET(kwonlyargs, j++, arg);
                i += 1; /* the name */
                if (TYPE(CHILD(n, i)) == COMMA)
                    i += 1; /* the comma, if present */
                break;
            case TYPE_COMMENT:
                /* arg will be equal to the last argument processed */
                arg->type_comment = NEW_TYPE_COMMENT(ch);
                if (!arg->type_comment)
                    goto error;
                i += 1;
                break;
            case DOUBLESTAR:
                return i;
            default:
                ast_error(c, ch, "unexpected node");
                goto error;
        }
    }
    return i;
 error:
    return -1;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1445,7 +1445,7 @@
                     goto error;
                 asdl_seq_SET(kwonlyargs, j++, arg);
                 i += 1; /* the name */
-                if (TYPE(CHILD(n, i)) == COMMA)
+                if (i < NCH(n) && TYPE(CHILD(n, i)) == COMMA)
                     i += 1; /* the comma, if present */
                 break;
             case TYPE_COMMENT:
@@ -1644,7 +1644,7 @@
                 if (!kwarg)
                     return NULL;
                 i += 2; /* the double star and the name */
-                if (TYPE(CHILD(n, i)) == COMMA)
+                if (i < NCH(n) && TYPE(CHILD(n, i)) == COMMA)
                     i += 1; /* the comma, if present */
                 break;
             case TYPE_COMMENT:
```
