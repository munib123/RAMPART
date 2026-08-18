# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 318_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `318_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 224-265 of the vulnerable file.

static const compile_file_fn compile_file_fns[LAST_KEYMAP_FILE_TYPE + 1] = {
    [FILE_TYPE_KEYCODES] = CompileKeycodes,
    [FILE_TYPE_TYPES] = CompileKeyTypes,
    [FILE_TYPE_COMPAT] = CompileCompatMap,
    [FILE_TYPE_SYMBOLS] = CompileSymbols,
};

bool
CompileKeymap(XkbFile *file, struct xkb_keymap *keymap, enum merge_mode merge)
{
    bool ok;
    XkbFile *files[LAST_KEYMAP_FILE_TYPE + 1] = { NULL };
    enum xkb_file_type type;
    struct xkb_context *ctx = keymap->ctx;

    /* Collect section files and check for duplicates. */
    for (file = (XkbFile *) file->defs; file;
         file = (XkbFile *) file->common.next) {
        if (file->file_type < FIRST_KEYMAP_FILE_TYPE ||
            file->file_type > LAST_KEYMAP_FILE_TYPE) {
            log_err(ctx, "Cannot define %s in a keymap file\n",
                    xkb_file_type_to_string(file->file_type));
            continue;
        }

        if (files[file->file_type]) {
            log_err(ctx,
                    "More than one %s section in keymap file; "
                    "All sections after the first ignored\n",
                    xkb_file_type_to_string(file->file_type));
            continue;
        }

        files[file->file_type] = file;
    }

    /*
     * Check that all required section were provided.
     * Report everything before failing.
     */
    ok = true;
    for (type = FIRST_KEYMAP_FILE_TYPE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -241,8 +241,13 @@
          file = (XkbFile *) file->common.next) {
         if (file->file_type < FIRST_KEYMAP_FILE_TYPE ||
             file->file_type > LAST_KEYMAP_FILE_TYPE) {
-            log_err(ctx, "Cannot define %s in a keymap file\n",
-                    xkb_file_type_to_string(file->file_type));
+            if (file->file_type == FILE_TYPE_GEOMETRY) {
+                log_vrb(ctx, 1,
+                        "Geometry sections are not supported; ignoring\n");
+            } else {
+                log_err(ctx, "Cannot define %s in a keymap file\n",
+                        xkb_file_type_to_string(file->file_type));
+            }
             continue;
         }
 
```
