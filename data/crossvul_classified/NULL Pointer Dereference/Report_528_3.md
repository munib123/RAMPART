# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 528_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `528_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3413-3453 of the vulnerable file.

	    bg->red = bg->blue;
	    bg->blue = tmp;
# endif
	}
# ifdef FEAT_TERMRESPONSE
	else
	    term_get_bg_color(&bg->red, &bg->green, &bg->blue);
# endif
    }
}

#if defined(FEAT_GUI) || defined(FEAT_TERMGUICOLORS)
/*
 * Set the 16 ANSI colors from array of RGB values
 */
    static void
set_vterm_palette(VTerm *vterm, long_u *rgb)
{
    int		index = 0;
    VTermState	*state = vterm_obtain_state(vterm);
    for (; index < 16; index++)
    {
	VTermColor	color;
	color.red = (unsigned)(rgb[index] >> 16);
	color.green = (unsigned)(rgb[index] >> 8) & 255;
	color.blue = (unsigned)rgb[index] & 255;
	vterm_state_set_palette_color(state, index, &color);
    }
}

/*
 * Set the ANSI color palette from a list of colors
 */
    static int
set_ansi_colors_list(VTerm *vterm, list_T *list)
{
    int		n = 0;
    long_u	rgb[16];
    listitem_T	*li = list->lv_first;

    for (; li != NULL && n < 16; li = li->li_next, n++)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3430,6 +3430,7 @@
 {
     int		index = 0;
     VTermState	*state = vterm_obtain_state(vterm);
+
     for (; index < 16; index++)
     {
 	VTermColor	color;
@@ -3703,8 +3704,9 @@
 
 /*
  * Create a new vterm and initialize it.
- */
-    static void
+ * Return FAIL when out of memory.
+ */
+    static int
 create_vterm(term_T *term, int rows, int cols)
 {
     VTerm	    *vterm;
@@ -3714,7 +3716,18 @@
 
     vterm = vterm_new_with_allocator(rows, cols, &vterm_allocator, NULL);
     term->tl_vterm = vterm;
+    if (vterm == NULL)
+	return FAIL;
+
+    // Allocate screen and state here, so we can bail out if that fails.
+    state = vterm_obtain_state(vterm);
     screen = vterm_obtain_screen(vterm);
+    if (state == NULL || screen == NULL)
+    {
+	vterm_free(vterm);
+	return FAIL;
+    }
+
     vterm_screen_set_callbacks(screen, &screen_callbacks, term);
     /* TODO: depends on 'encoding'. */
     vterm_set_utf8(vterm, 1);
@@ -3722,7 +3735,7 @@
     init_default_colors(term);
 
     vterm_state_set_default_colors(
-	    vterm_obtain_state(vterm),
+	    state,
 	    &term->tl_default_color.fg,
 	    &term->tl_default_color.bg);
 
@@ -3746,9 +3759,10 @@
 #else
     value.boolean = 0;
 #endif
-    state = vterm_obtain_state(vterm);
     vterm_state_set_termprop(state, VTERM_PROP_CURSORBLINK, &value);
     vterm_state_set_unrecognised_fallbacks(state, &parser_fallbacks, term);
+
+    return OK;
 }
 
 /*
@@ -5629,7 +5643,8 @@
     vim_free(cwd_wchar);
     vim_free(env_wchar);
 
-    create_vterm(term, term->tl_rows, term->tl_cols);
+    if (create_vterm(term, term->tl_rows, term->tl_cols) == FAIL)
+	goto failed;
 
 #if defined(FEAT_GUI) || defined(FEAT_TERMGUICOLORS)
     if (opt->jo_set2 & JO2_ANSI_COLORS)
@@ -5710,7 +5725,8 @@
     char	    in_name[80], out_name[80];
     channel_T	    *channel = NULL;
 
-    create_vterm(term, term->tl_rows, term->tl_cols);
+    if (create_vterm(term, term->tl_rows, term->tl_cols) == FAIL)
+	return FAIL;
 
     vim_snprintf(in_name, sizeof(in_name), "\\\\.\\pipe\\vim-%d-in-%d",
 	    GetCurrentProcessId(),
@@ -5822,7 +5838,8 @@
 	jobopt_T    *opt,
 	jobopt_T    *orig_opt UNUSED)
 {
-    create_vterm(term, term->tl_rows, term->tl_cols);
+    if (create_vterm(term, term->tl_rows, term->tl_cols) == FAIL)
+	return FAIL;
 
 #if defined(FEAT_GUI) || defined(FEAT_TERMGUICOLORS)
     if (opt->jo_set2 & JO2_ANSI_COLORS)
@@ -5844,7 +5861,8 @@
     static int
 create_pty_only(term_T *term, jobopt_T *opt)
 {
-    create_vterm(term, term->tl_rows, term->tl_cols);
+    if (create_vterm(term, term->tl_rows, term->tl_cols) == FAIL)
+	return FAIL;
 
     term->tl_job = job_alloc();
     if (term->tl_job == NULL)
```
