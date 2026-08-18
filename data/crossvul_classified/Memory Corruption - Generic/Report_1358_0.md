# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1358_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1358_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1385-1425 of the vulnerable file.

        return resolve_iffeature_recursive(expr, index_e, index_f) ? 0 : 1;
    case LYS_IFF_AND:
    case LYS_IFF_OR:
        a = resolve_iffeature_recursive(expr, index_e, index_f);
        b = resolve_iffeature_recursive(expr, index_e, index_f);
        if (op == LYS_IFF_AND) {
            return a && b;
        } else { /* LYS_IFF_OR */
            return a || b;
        }
    }

    return 0;
}

int
resolve_iffeature(struct lys_iffeature *expr)
{
    int index_e = 0, index_f = 0;

    if (expr->expr) {
        return resolve_iffeature_recursive(expr, &index_e, &index_f);
    }
    return 0;
}

struct iff_stack {
    int size;
    int index;     /* first empty item */
    uint8_t *stack;
};

static int
iff_stack_push(struct iff_stack *stack, uint8_t value)
{
    if (stack->index == stack->size) {
        stack->size += 4;
        stack->stack = ly_realloc(stack->stack, stack->size * sizeof *stack->stack);
        LY_CHECK_ERR_RETURN(!stack->stack, LOGMEM(NULL); stack->size = 0, EXIT_FAILURE);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1402,7 +1402,7 @@
 {
     int index_e = 0, index_f = 0;
 
-    if (expr->expr) {
+    if (expr->expr && expr->features[0]) {
         return resolve_iffeature_recursive(expr, &index_e, &index_f);
     }
     return 0;
```
