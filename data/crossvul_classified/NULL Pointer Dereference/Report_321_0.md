# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 321_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `321_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 579-619 of the vulnerable file.

        /* Check that ->alias is not a key. */
        if (XkbKeyByName(keymap, alias->alias, false)) {
            log_vrb(info->ctx, 5,
                    "Attempt to create alias with the name of a real key; "
                    "Alias \"%s = %s\" ignored\n",
                    KeyNameText(info->ctx, alias->alias),
                    KeyNameText(info->ctx, alias->real));
            alias->real = XKB_ATOM_NONE;
            continue;
        }

        num_key_aliases++;
    }

    /* Copy key aliases. */
    key_aliases = NULL;
    if (num_key_aliases > 0) {
        key_aliases = calloc(num_key_aliases, sizeof(*key_aliases));
        if (!key_aliases)
            return false;
    }

    i = 0;
    darray_foreach(alias, info->aliases) {
        if (alias->real != XKB_ATOM_NONE) {
            key_aliases[i].alias = alias->alias;
            key_aliases[i].real = alias->real;
            i++;
        }
    }

    keymap->num_key_aliases = num_key_aliases;
    keymap->key_aliases = key_aliases;
    return true;
}

static bool
CopyLedNamesToKeymap(struct xkb_keymap *keymap, KeyNamesInfo *info)
{
    keymap->num_leds = info->num_led_names;
    for (xkb_led_index_t idx = 0; idx < info->num_led_names; idx++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -596,14 +596,14 @@
         key_aliases = calloc(num_key_aliases, sizeof(*key_aliases));
         if (!key_aliases)
             return false;
-    }
-
-    i = 0;
-    darray_foreach(alias, info->aliases) {
-        if (alias->real != XKB_ATOM_NONE) {
-            key_aliases[i].alias = alias->alias;
-            key_aliases[i].real = alias->real;
-            i++;
+
+        i = 0;
+        darray_foreach(alias, info->aliases) {
+            if (alias->real != XKB_ATOM_NONE) {
+                key_aliases[i].alias = alias->alias;
+                key_aliases[i].real = alias->real;
+                i++;
+            }
         }
     }
 
```
