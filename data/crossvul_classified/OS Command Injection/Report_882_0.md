# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 882_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `882_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 1390-1430 of the vulnerable file.

    free_buff(&readbuf2);
    readbuf2 = tp->save_readbuf2;
# ifdef USE_INPUT_BUF
    set_input_buf(tp->save_inputbuf);
# endif
}

/*
 * Open a new script file for the ":source!" command.
 */
    void
openscript(
    char_u	*name,
    int		directly)	/* when TRUE execute directly */
{
    if (curscript + 1 == NSCRIPT)
    {
	emsg(_(e_nesting));
	return;
    }
#ifdef FEAT_EVAL
    if (ignore_script)
	/* Not reading from script, also don't open one.  Warning message? */
	return;
#endif

    if (scriptin[curscript] != NULL)	/* already reading script */
	++curscript;
				/* use NameBuff for expanded name */
    expand_env(name, NameBuff, MAXPATHL);
    if ((scriptin[curscript] = mch_fopen((char *)NameBuff, READBIN)) == NULL)
    {
	semsg(_(e_notopen), name);
	if (curscript)
	    --curscript;
	return;
    }
    if (save_typebuf() == FAIL)
	return;

    /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1407,6 +1407,12 @@
 	emsg(_(e_nesting));
 	return;
     }
+
+    // Disallow sourcing a file in the sandbox, the commands would be executed
+    // later, possibly outside of the sandbox.
+    if (check_secure())
+	return;
+
 #ifdef FEAT_EVAL
     if (ignore_script)
 	/* Not reading from script, also don't open one.  Warning message? */
```
