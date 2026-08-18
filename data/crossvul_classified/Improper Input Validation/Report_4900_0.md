# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4900_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4900_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 5806-5846 of the vulnerable file.

	/* call autocomamnd after handling side effects */
#if defined(FEAT_AUTOCMD) && defined(FEAT_EVAL)
	if (saved_oldval != NULL)
	{
	    char_u buf_type[7];
	    sprintf((char *)buf_type, "%s",
		(opt_flags & OPT_LOCAL) ? "local" : "global");
	    set_vim_var_string(VV_OPTION_NEW, *varp, -1);
	    set_vim_var_string(VV_OPTION_OLD, saved_oldval, -1);
	    set_vim_var_string(VV_OPTION_TYPE, buf_type, -1);
	    apply_autocmds(EVENT_OPTIONSET, (char_u *)options[opt_idx].fullname, NULL, FALSE, NULL);
	    reset_v_option_vars();
	    vim_free(saved_oldval);
	}
#endif
    }
    return r;
}

/*
 * Handle string options that need some action to perform when changed.
 * Returns NULL for success, or an error message for an error.
 */
    static char_u *
did_set_string_option(
    int		opt_idx,		/* index in options[] table */
    char_u	**varp,			/* pointer to the option variable */
    int		new_value_alloced,	/* new value was allocated */
    char_u	*oldval,		/* previous value of the option */
    char_u	*errbuf,		/* buffer for errors, or NULL */
    int		opt_flags)		/* OPT_LOCAL and/or OPT_GLOBAL */
{
    char_u	*errmsg = NULL;
    char_u	*s, *p;
    int		did_chartab = FALSE;
    char_u	**gvarp;
    long_u	free_oldval = (options[opt_idx].flags & P_ALLOCED);
#ifdef FEAT_GUI
    /* set when changing an option that only requires a redraw in the GUI */
    int		redraw_gui_only = FALSE;
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5823,6 +5823,21 @@
 }
 
 /*
+ * Return TRUE if "val" is a valid 'filetype' name.
+ * Also used for 'syntax' and 'keymap'.
+ */
+    static int
+valid_filetype(char_u *val)
+{
+    char_u *s;
+
+    for (s = val; *s != NUL; ++s)
+	if (!ASCII_ISALNUM(*s) && vim_strchr((char_u *)".-_", *s) == NULL)
+	    return FALSE;
+    return TRUE;
+}
+
+/*
  * Handle string options that need some action to perform when changed.
  * Returns NULL for success, or an error message for an error.
  */
@@ -6235,8 +6250,11 @@
 #ifdef FEAT_KEYMAP
     else if (varp == &curbuf->b_p_keymap)
     {
-	/* load or unload key mapping tables */
-	errmsg = keymap_init();
+	if (!valid_filetype(*varp))
+	    errmsg = e_invarg;
+	else
+	    /* load or unload key mapping tables */
+	    errmsg = keymap_init();
 
 	if (errmsg == NULL)
 	{
@@ -7218,6 +7236,22 @@
     else if (varp == &p_rop && gui.in_use)
     {
 	if (!gui_mch_set_rendering_options(p_rop))
+	    errmsg = e_invarg;
+    }
+#endif
+
+#ifdef FEAT_AUTOCMD
+    else if (gvarp == &p_ft)
+    {
+	if (!valid_filetype(*varp))
+	    errmsg = e_invarg;
+    }
+#endif
+
+#ifdef FEAT_SYN_HL
+    else if (gvarp == &p_syn)
+    {
+	if (!valid_filetype(*varp))
 	    errmsg = e_invarg;
     }
 #endif
```
