# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 316_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `316_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 148-188 of the vulnerable file.

                return true;
            }
            else if (istreq(ident, "false") ||
                     istreq(ident, "no") ||
                     istreq(ident, "off")) {
                *set_rtrn = false;
                return true;
            }
        }
        log_err(ctx, "Identifier \"%s\" of type boolean is unknown\n", ident);
        return false;

    case EXPR_FIELD_REF:
        log_err(ctx, "Default \"%s.%s\" of type boolean is unknown\n",
                xkb_atom_text(ctx, expr->field_ref.element),
                xkb_atom_text(ctx, expr->field_ref.field));
        return false;

    case EXPR_INVERT:
    case EXPR_NOT:
        ok = ExprResolveBoolean(ctx, expr, set_rtrn);
        if (ok)
            *set_rtrn = !*set_rtrn;
        return ok;
    case EXPR_ADD:
    case EXPR_SUBTRACT:
    case EXPR_MULTIPLY:
    case EXPR_DIVIDE:
    case EXPR_ASSIGN:
    case EXPR_NEGATE:
    case EXPR_UNARY_PLUS:
        log_err(ctx, "%s of boolean values not permitted\n",
                expr_op_type_to_string(expr->expr.op));
        break;

    default:
        log_wsgo(ctx, "Unknown operator %d in ResolveBoolean\n",
                 expr->expr.op);
        break;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,7 +165,7 @@
 
     case EXPR_INVERT:
     case EXPR_NOT:
-        ok = ExprResolveBoolean(ctx, expr, set_rtrn);
+        ok = ExprResolveBoolean(ctx, expr->unary.child, set_rtrn);
         if (ok)
             *set_rtrn = !*set_rtrn;
         return ok;
```
