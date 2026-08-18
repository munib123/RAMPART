# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4899_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4899_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2382-2422 of the vulnerable file.

  }

  // call autocommand after handling side effects
  if (saved_oldval != NULL) {
    char buf_type[7];
    vim_snprintf(buf_type, ARRAY_SIZE(buf_type), "%s",
                 (opt_flags & OPT_LOCAL) ? "local" : "global");
    set_vim_var_string(VV_OPTION_NEW, (char *)(*varp), -1);
    set_vim_var_string(VV_OPTION_OLD, saved_oldval, -1);
    set_vim_var_string(VV_OPTION_TYPE, buf_type, -1);
    apply_autocmds(EVENT_OPTIONSET,
                   (char_u *)options[opt_idx].fullname,
                   NULL, false, NULL);
    reset_v_option_vars();
    xfree(saved_oldval);
  }

  return r;
}

/*
 * Handle string options that need some action to perform when changed.
 * Returns NULL for success, or an error message for an error.
 */
static char_u *
did_set_string_option (
    int opt_idx,                            /* index in options[] table */
    char_u **varp,                     /* pointer to the option variable */
    int new_value_alloced,                  /* new value was allocated */
    char_u *oldval,                    /* previous value of the option */
    char_u *errbuf,                    /* buffer for errors, or NULL */
    int opt_flags                          /* OPT_LOCAL and/or OPT_GLOBAL */
)
{
  char_u      *errmsg = NULL;
  char_u      *s, *p;
  int did_chartab = FALSE;
  char_u      **gvarp;
  bool free_oldval = (options[opt_idx].flags & P_ALLOCED);

  /* Get the global option to compare with, otherwise we would have to check
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2399,6 +2399,18 @@
   return r;
 }
 
+/// Return true if "val" is a valid 'filetype' name.
+/// Also used for 'syntax' and 'keymap'.
+static bool valid_filetype(char_u *val)
+{
+  for (char_u *s = val; *s != NUL; s++) {
+    if (!ASCII_ISALNUM(*s) && vim_strchr((char_u *)".-_", *s) == NULL) {
+      return false;
+    }
+  }
+  return true;
+}
+
 /*
  * Handle string options that need some action to perform when changed.
  * Returns NULL for success, or an error message for an error.
@@ -2623,8 +2635,12 @@
     xfree(p_penc);
     p_penc = p;
   } else if (varp == &curbuf->b_p_keymap) {
-    /* load or unload key mapping tables */
-    errmsg = keymap_init();
+    if (!valid_filetype(*varp)) {
+      errmsg = e_invarg;
+    } else {
+      // load or unload key mapping tables
+      errmsg = keymap_init();
+    }
 
     if (errmsg == NULL) {
       if (*curbuf->b_p_keymap != NUL) {
@@ -3118,8 +3134,16 @@
       if (check_opt_strings(p_icm, p_icm_values, false) != OK) {
         errmsg = e_invarg;
       }
-  // Options that are a list of flags.
+  } else if (gvarp == &p_ft) {
+    if (!valid_filetype(*varp)) {
+      errmsg = e_invarg;
+    }
+  } else if (gvarp == &p_syn) {
+    if (!valid_filetype(*varp)) {
+      errmsg = e_invarg;
+    }
   } else {
+    // Options that are a list of flags.
     p = NULL;
     if (varp == &p_ww)
       p = (char_u *)WW_ALL;
```
