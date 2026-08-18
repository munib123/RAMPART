# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1342_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1342_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 4624-4664 of the vulnerable file.

	if (curwin->w_localdir != NULL)
	    dirname = curwin->w_localdir;
	else
	    dirname = curtab->tp_localdir;

	if (mch_chdir((char *)dirname) == 0)
	    shorten_fnames(TRUE);
    }
    else if (globaldir != NULL)
    {
	/* Window doesn't have a local directory and we are not in the global
	 * directory: Change to the global directory. */
	vim_ignored = mch_chdir((char *)globaldir);
	VIM_CLEAR(globaldir);
	shorten_fnames(TRUE);
    }

#ifdef FEAT_JOB_CHANNEL
    entering_window(curwin);
#endif
    if (trigger_new_autocmds)
	apply_autocmds(EVENT_WINNEW, NULL, NULL, FALSE, curbuf);
    if (trigger_enter_autocmds)
    {
	apply_autocmds(EVENT_WINENTER, NULL, NULL, FALSE, curbuf);
	if (other_buffer)
	    apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);
    }

#ifdef FEAT_TITLE
    maketitle();
#endif
    curwin->w_redr_status = TRUE;
#ifdef FEAT_TERMINAL
    if (bt_terminal(wp->w_buffer))
	// terminal is likely in another mode
	redraw_mode = TRUE;
#endif
    redraw_tabline = TRUE;
    if (restart_edit)
	redraw_later(VALID);	/* causes status line redraw */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4641,6 +4641,7 @@
 #ifdef FEAT_JOB_CHANNEL
     entering_window(curwin);
 #endif
+    // Careful: autocommands may close the window and make "wp" invalid
     if (trigger_new_autocmds)
 	apply_autocmds(EVENT_WINNEW, NULL, NULL, FALSE, curbuf);
     if (trigger_enter_autocmds)
@@ -4655,7 +4656,7 @@
 #endif
     curwin->w_redr_status = TRUE;
 #ifdef FEAT_TERMINAL
-    if (bt_terminal(wp->w_buffer))
+    if (bt_terminal(curwin->w_buffer))
 	// terminal is likely in another mode
 	redraw_mode = TRUE;
 #endif
```
